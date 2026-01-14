"""
Access Review Ceremonies for Compliance

Implements periodic access review ceremonies required by:
- SOC 2 Type II
- ISO 27001 (A.9.2.5)
- NIST 800-53 (AC-2)
- PCI DSS (Requirement 8)

Access reviews require human ceremony approval and generate
auditable records of review decisions.
"""

import hashlib
import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class ReviewScope(Enum):
    """Scope of access review."""
    ALL_USERS = "all_users"
    PRIVILEGED_USERS = "privileged_users"
    SERVICE_ACCOUNTS = "service_accounts"
    EXTERNAL_USERS = "external_users"
    SPECIFIC_CAPABILITY = "specific_capability"
    SPECIFIC_RESOURCE = "specific_resource"


class ReviewDecision(Enum):
    """Decision for an access review item."""
    APPROVE = "approve"           # Access confirmed appropriate
    REVOKE = "revoke"             # Access should be removed
    MODIFY = "modify"             # Access should be changed
    ESCALATE = "escalate"         # Needs higher authority review
    DEFER = "defer"               # Review postponed (with reason)


class ReviewStatus(Enum):
    """Status of access review."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    OVERDUE = "overdue"


@dataclass
class AccessItem:
    """An access right to be reviewed."""
    item_id: str
    subject: str  # User or service account
    subject_type: str  # "user", "service_account", "group"
    resource: str  # What they have access to
    capability: str  # What they can do
    granted_at: datetime
    granted_by: str
    last_used: Optional[datetime] = None
    justification: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReviewItem:
    """A single item in an access review."""
    access_item: AccessItem
    decision: Optional[ReviewDecision] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    notes: Optional[str] = None
    new_capability: Optional[str] = None  # For MODIFY decisions


@dataclass
class AccessReviewRecord:
    """Complete record of an access review."""
    review_id: str
    scope: ReviewScope
    scope_filter: Optional[str]  # e.g., specific capability name

    # Timing
    created_at: datetime
    due_date: datetime

    # Participants (must come before fields with defaults)
    initiated_by: str

    # Fields with defaults
    completed_at: Optional[datetime] = None
    reviewers: List[str] = field(default_factory=list)
    approvers: List[str] = field(default_factory=list)

    # Items
    items: List[ReviewItem] = field(default_factory=list)
    status: ReviewStatus = ReviewStatus.PENDING

    # Ceremony
    ceremony_id: Optional[str] = None
    ceremony_completed: bool = False

    # Summary
    approved_count: int = 0
    revoked_count: int = 0
    modified_count: int = 0
    escalated_count: int = 0
    deferred_count: int = 0

    # Audit
    hash_chain: Optional[str] = None
    signature: Optional[str] = None

    def calculate_summary(self) -> None:
        """Calculate decision summary."""
        self.approved_count = sum(
            1 for i in self.items if i.decision == ReviewDecision.APPROVE
        )
        self.revoked_count = sum(
            1 for i in self.items if i.decision == ReviewDecision.REVOKE
        )
        self.modified_count = sum(
            1 for i in self.items if i.decision == ReviewDecision.MODIFY
        )
        self.escalated_count = sum(
            1 for i in self.items if i.decision == ReviewDecision.ESCALATE
        )
        self.deferred_count = sum(
            1 for i in self.items if i.decision == ReviewDecision.DEFER
        )


@dataclass
class AccessReviewCeremony:
    """
    A ceremony for conducting access reviews.

    Requires human approval to complete the review.
    """
    review_id: str
    ceremony_type: str = "ACCESS_REVIEW"

    # Challenge
    challenge_phrase: str = ""
    challenge_hash: str = ""

    # Approval requirements
    required_approvers: int = 1
    approvals_received: List[str] = field(default_factory=list)

    # Status
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expired_at: Optional[datetime] = None

    @property
    def is_complete(self) -> bool:
        """Check if ceremony has required approvals."""
        return len(self.approvals_received) >= self.required_approvers

    @property
    def is_expired(self) -> bool:
        """Check if ceremony has expired."""
        if self.expired_at is None:
            return False
        return datetime.utcnow() > self.expired_at


class AccessReviewManager:
    """
    Manages access review ceremonies.

    Usage:
        manager = AccessReviewManager()

        # Register access source
        manager.register_access_source(my_access_provider)

        # Create a review
        review = manager.create_review(
            scope=ReviewScope.PRIVILEGED_USERS,
            initiated_by="admin@example.com",
            reviewers=["security@example.com"],
            due_days=14,
        )

        # Start ceremony
        ceremony = manager.start_ceremony(review.review_id)

        # Record decisions
        manager.record_decision(
            review.review_id,
            item_id,
            ReviewDecision.APPROVE,
            decided_by="security@example.com",
        )

        # Complete ceremony
        manager.complete_ceremony(
            review.review_id,
            approver="admin@example.com",
            challenge_response="...",
        )
    """

    def __init__(
        self,
        ceremony_timeout_hours: int = 72,
        required_approvers: int = 1,
    ):
        self.ceremony_timeout_hours = ceremony_timeout_hours
        self.required_approvers = required_approvers
        self._lock = threading.Lock()

        # Active reviews
        self._reviews: Dict[str, AccessReviewRecord] = {}
        self._ceremonies: Dict[str, AccessReviewCeremony] = {}

        # Access data sources
        self._access_sources: List[Callable[[], List[AccessItem]]] = []

        # Event callbacks
        self._on_review_complete: Optional[Callable[[AccessReviewRecord], None]] = None
        self._on_revocation: Optional[Callable[[AccessItem], None]] = None

    def register_access_source(
        self,
        source: Callable[[], List[AccessItem]],
    ) -> None:
        """Register a source of access data."""
        self._access_sources.append(source)

    def set_completion_callback(
        self,
        callback: Callable[[AccessReviewRecord], None],
    ) -> None:
        """Set callback for review completion."""
        self._on_review_complete = callback

    def set_revocation_callback(
        self,
        callback: Callable[[AccessItem], None],
    ) -> None:
        """Set callback for access revocation."""
        self._on_revocation = callback

    def _generate_review_id(self) -> str:
        """Generate unique review ID."""
        return f"review_{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"

    def _generate_challenge(self) -> tuple[str, str]:
        """Generate review challenge phrase and hash."""
        phrase = f"ACCESS-REVIEW-{uuid.uuid4().hex[:8].upper()}"
        hash_value = hashlib.sha256(phrase.encode()).hexdigest()
        return phrase, hash_value

    def _collect_access_items(
        self,
        scope: ReviewScope,
        scope_filter: Optional[str] = None,
    ) -> List[AccessItem]:
        """Collect access items from all sources."""
        items: List[AccessItem] = []

        for source in self._access_sources:
            try:
                source_items = source()
                items.extend(source_items)
            except Exception as e:
                logger.error(f"Failed to collect from access source: {e}")

        # Filter by scope
        if scope == ReviewScope.PRIVILEGED_USERS:
            items = [i for i in items if i.subject_type == "user" and
                     i.capability in {"admin", "write", "delete", "execute"}]
        elif scope == ReviewScope.SERVICE_ACCOUNTS:
            items = [i for i in items if i.subject_type == "service_account"]
        elif scope == ReviewScope.EXTERNAL_USERS:
            items = [i for i in items if i.metadata.get("external", False)]
        elif scope == ReviewScope.SPECIFIC_CAPABILITY and scope_filter:
            items = [i for i in items if i.capability == scope_filter]
        elif scope == ReviewScope.SPECIFIC_RESOURCE and scope_filter:
            items = [i for i in items if i.resource == scope_filter]

        return items

    def create_review(
        self,
        scope: ReviewScope,
        initiated_by: str,
        reviewers: List[str],
        due_days: int = 14,
        scope_filter: Optional[str] = None,
        approvers: Optional[List[str]] = None,
    ) -> AccessReviewRecord:
        """
        Create a new access review.

        Args:
            scope: Scope of the review
            initiated_by: Identity of initiator
            reviewers: List of reviewer identities
            due_days: Days until due
            scope_filter: Filter for specific scope types
            approvers: List of required approvers (defaults to reviewers)

        Returns:
            AccessReviewRecord
        """
        review_id = self._generate_review_id()

        # Collect access items
        access_items = self._collect_access_items(scope, scope_filter)

        # Create review items
        review_items = [
            ReviewItem(access_item=item)
            for item in access_items
        ]

        review = AccessReviewRecord(
            review_id=review_id,
            scope=scope,
            scope_filter=scope_filter,
            created_at=datetime.utcnow(),
            due_date=datetime.utcnow() + timedelta(days=due_days),
            initiated_by=initiated_by,
            reviewers=reviewers,
            approvers=approvers or reviewers,
            items=review_items,
            status=ReviewStatus.PENDING,
        )

        with self._lock:
            self._reviews[review_id] = review

        logger.info(
            f"Created access review {review_id} with {len(review_items)} items"
        )

        return review

    def start_ceremony(self, review_id: str) -> Optional[AccessReviewCeremony]:
        """
        Start the ceremony for an access review.

        Args:
            review_id: Review to start ceremony for

        Returns:
            AccessReviewCeremony or None if review not found
        """
        with self._lock:
            review = self._reviews.get(review_id)
            if not review:
                return None

            # Generate challenge
            phrase, hash_value = self._generate_challenge()

            ceremony = AccessReviewCeremony(
                review_id=review_id,
                challenge_phrase=phrase,
                challenge_hash=hash_value,
                required_approvers=self.required_approvers,
                started_at=datetime.utcnow(),
                expired_at=datetime.utcnow() + timedelta(
                    hours=self.ceremony_timeout_hours
                ),
            )

            self._ceremonies[review_id] = ceremony
            review.ceremony_id = review_id
            review.status = ReviewStatus.IN_PROGRESS

        logger.info(f"Started ceremony for review {review_id}")
        return ceremony

    def record_decision(
        self,
        review_id: str,
        item_id: str,
        decision: ReviewDecision,
        decided_by: str,
        notes: Optional[str] = None,
        new_capability: Optional[str] = None,
    ) -> bool:
        """
        Record a decision for a review item.

        Args:
            review_id: Review ID
            item_id: Item ID within review
            decision: The decision
            decided_by: Who made the decision
            notes: Optional notes
            new_capability: New capability for MODIFY decisions

        Returns:
            True if decision recorded
        """
        with self._lock:
            review = self._reviews.get(review_id)
            if not review:
                return False

            # Find item
            for item in review.items:
                if item.access_item.item_id == item_id:
                    item.decision = decision
                    item.decided_at = datetime.utcnow()
                    item.decided_by = decided_by
                    item.notes = notes
                    if decision == ReviewDecision.MODIFY:
                        item.new_capability = new_capability
                    return True

            return False

    def approve_ceremony(
        self,
        review_id: str,
        approver: str,
        challenge_response: str,
    ) -> tuple[bool, str]:
        """
        Submit ceremony approval.

        Args:
            review_id: Review ID
            approver: Approver identity
            challenge_response: Response to challenge phrase

        Returns:
            (success, message)
        """
        with self._lock:
            ceremony = self._ceremonies.get(review_id)
            review = self._reviews.get(review_id)

            if not ceremony or not review:
                return (False, "Review or ceremony not found")

            if ceremony.is_expired:
                return (False, "Ceremony has expired")

            # Verify challenge response
            response_hash = hashlib.sha256(
                challenge_response.encode()
            ).hexdigest()

            if response_hash != ceremony.challenge_hash:
                return (False, "Invalid challenge response")

            # Check approver is authorized
            if approver not in review.approvers:
                return (False, f"Approver {approver} not authorized")

            # Record approval
            if approver not in ceremony.approvals_received:
                ceremony.approvals_received.append(approver)

            # Check if complete
            if ceremony.is_complete:
                ceremony.completed_at = datetime.utcnow()
                return (True, "Ceremony complete - all approvals received")
            else:
                remaining = ceremony.required_approvers - len(
                    ceremony.approvals_received
                )
                return (True, f"Approval recorded - {remaining} more needed")

    def complete_review(self, review_id: str) -> tuple[bool, str]:
        """
        Complete an access review after ceremony.

        Args:
            review_id: Review ID

        Returns:
            (success, message)
        """
        with self._lock:
            ceremony = self._ceremonies.get(review_id)
            review = self._reviews.get(review_id)

            if not ceremony or not review:
                return (False, "Review or ceremony not found")

            if not ceremony.is_complete:
                return (False, "Ceremony not complete")

            # Check all items have decisions
            undecided = [i for i in review.items if i.decision is None]
            if undecided:
                return (
                    False,
                    f"{len(undecided)} items still need decisions"
                )

            # Calculate summary
            review.calculate_summary()
            review.completed_at = datetime.utcnow()
            review.ceremony_completed = True
            review.status = ReviewStatus.COMPLETED

            # Generate audit hash
            audit_data = json.dumps({
                'review_id': review.review_id,
                'completed_at': review.completed_at.isoformat(),
                'summary': {
                    'approved': review.approved_count,
                    'revoked': review.revoked_count,
                    'modified': review.modified_count,
                },
                'approvers': ceremony.approvals_received,
            }, sort_keys=True)
            review.hash_chain = hashlib.sha256(audit_data.encode()).hexdigest()

        # Execute revocations
        for item in review.items:
            if item.decision == ReviewDecision.REVOKE:
                if self._on_revocation:
                    try:
                        self._on_revocation(item.access_item)
                    except Exception as e:
                        logger.error(f"Revocation callback failed: {e}")

        # Notify completion
        if self._on_review_complete:
            try:
                self._on_review_complete(review)
            except Exception as e:
                logger.error(f"Completion callback failed: {e}")

        logger.info(
            f"Completed review {review_id}: "
            f"{review.approved_count} approved, {review.revoked_count} revoked"
        )

        return (True, "Review completed successfully")

    def get_review(self, review_id: str) -> Optional[AccessReviewRecord]:
        """Get a review by ID."""
        return self._reviews.get(review_id)

    def get_pending_reviews(self) -> List[AccessReviewRecord]:
        """Get all pending reviews."""
        return [
            r for r in self._reviews.values()
            if r.status in (ReviewStatus.PENDING, ReviewStatus.IN_PROGRESS)
        ]

    def get_overdue_reviews(self) -> List[AccessReviewRecord]:
        """Get all overdue reviews."""
        now = datetime.utcnow()
        overdue = []
        for review in self._reviews.values():
            if review.status in (ReviewStatus.PENDING, ReviewStatus.IN_PROGRESS):
                if review.due_date < now:
                    review.status = ReviewStatus.OVERDUE
                    overdue.append(review)
        return overdue

    def export_review(
        self,
        review_id: str,
        output_path: str,
    ) -> bool:
        """Export review record to JSON."""
        review = self._reviews.get(review_id)
        if not review:
            return False

        try:
            data = {
                'review_id': review.review_id,
                'scope': review.scope.value,
                'status': review.status.value,
                'created_at': review.created_at.isoformat() + 'Z',
                'due_date': review.due_date.isoformat() + 'Z',
                'completed_at': (
                    review.completed_at.isoformat() + 'Z'
                    if review.completed_at else None
                ),
                'initiated_by': review.initiated_by,
                'reviewers': review.reviewers,
                'approvers': review.approvers,
                'summary': {
                    'total': len(review.items),
                    'approved': review.approved_count,
                    'revoked': review.revoked_count,
                    'modified': review.modified_count,
                    'escalated': review.escalated_count,
                    'deferred': review.deferred_count,
                },
                'items': [
                    {
                        'item_id': item.access_item.item_id,
                        'subject': item.access_item.subject,
                        'resource': item.access_item.resource,
                        'capability': item.access_item.capability,
                        'decision': item.decision.value if item.decision else None,
                        'decided_by': item.decided_by,
                        'notes': item.notes,
                    }
                    for item in review.items
                ],
                'hash_chain': review.hash_chain,
            }

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Failed to export review: {e}")
            return False


if __name__ == '__main__':
    print("Testing Access Review Manager...")

    manager = AccessReviewManager(
        ceremony_timeout_hours=72,
        required_approvers=1,
    )

    # Register mock access source
    def mock_access_source() -> List[AccessItem]:
        return [
            AccessItem(
                item_id="access_1",
                subject="admin@example.com",
                subject_type="user",
                resource="boundary-daemon",
                capability="admin",
                granted_at=datetime.utcnow() - timedelta(days=90),
                granted_by="system",
            ),
            AccessItem(
                item_id="access_2",
                subject="operator@example.com",
                subject_type="user",
                resource="boundary-daemon",
                capability="write",
                granted_at=datetime.utcnow() - timedelta(days=30),
                granted_by="admin@example.com",
            ),
            AccessItem(
                item_id="access_3",
                subject="svc-backup",
                subject_type="service_account",
                resource="log-storage",
                capability="read",
                granted_at=datetime.utcnow() - timedelta(days=180),
                granted_by="system",
            ),
        ]

    manager.register_access_source(mock_access_source)

    # Create review
    review = manager.create_review(
        scope=ReviewScope.ALL_USERS,
        initiated_by="security@example.com",
        reviewers=["security@example.com"],
        due_days=14,
    )

    print(f"\nCreated review:")
    print(f"  ID: {review.review_id}")
    print(f"  Scope: {review.scope.value}")
    print(f"  Items: {len(review.items)}")
    print(f"  Due: {review.due_date}")

    # Start ceremony
    ceremony = manager.start_ceremony(review.review_id)
    print(f"\nCeremony started:")
    print(f"  Challenge: {ceremony.challenge_phrase}")
    print(f"  Expires: {ceremony.expired_at}")

    # Record decisions
    for item in review.items:
        manager.record_decision(
            review.review_id,
            item.access_item.item_id,
            ReviewDecision.APPROVE,
            decided_by="security@example.com",
            notes="Access still required",
        )

    print(f"\nRecorded {len(review.items)} decisions")

    # Approve ceremony
    success, msg = manager.approve_ceremony(
        review.review_id,
        approver="security@example.com",
        challenge_response=ceremony.challenge_phrase,
    )
    print(f"\nCeremony approval: {msg}")

    # Complete review
    success, msg = manager.complete_review(review.review_id)
    print(f"Review completion: {msg}")

    # Show summary
    print(f"\nReview summary:")
    print(f"  Approved: {review.approved_count}")
    print(f"  Revoked: {review.revoked_count}")
    print(f"  Modified: {review.modified_count}")
    print(f"  Hash: {review.hash_chain[:32]}...")

    print("\nAccess review test complete.")
