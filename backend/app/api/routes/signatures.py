"""
Signature management API routes.

Provides endpoints for CRUD operations on detection signatures.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_database, Pagination
from app.models.signature import Signature, SeverityLevel, ProtocolType
from app.schemas.signature import (
    SignatureCreate,
    SignatureUpdate,
    SignatureResponse,
    SignatureList,
)
from app.api.deps import get_detector
from app.core.logging import ids_logger

router = APIRouter()


@router.get(
    "/",
    response_model=SignatureList,
    summary="Get all signatures",
    description="Retrieve a paginated list of signatures with optional filters.",
)
def get_signatures(
    pagination: Pagination = Depends(),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    db: Session = Depends(get_database),
):
    """
    Get all signatures with pagination and filtering.

    Supports filtering by:
    - Enabled status
    - Severity level
    - Category
    - Text search in name/description

    Returns paginated results ordered by name.
    """
    query = db.query(Signature)

    # Apply filters
    if enabled is not None:
        query = query.filter(Signature.enabled == enabled)
    if severity:
        query = query.filter(Signature.severity == severity)
    if category:
        query = query.filter(Signature.category == category)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Signature.name.ilike(search_term))
            | (Signature.description.ilike(search_term))
        )

    # Get total count
    total = query.count()

    # Get paginated results
    signatures = (
        query.order_by(Signature.name)
        .offset(pagination.skip)
        .limit(pagination.limit)
        .all()
    )

    return SignatureList(
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        signatures=[SignatureResponse.model_validate(s) for s in signatures],
    )


@router.get(
    "/categories",
    summary="Get signature categories",
    description="Get list of all unique signature categories.",
)
def get_categories(db: Session = Depends(get_database)):
    """
    Get all unique signature categories.

    Useful for populating filter dropdowns.
    """
    categories = (
        db.query(Signature.category)
        .filter(Signature.category.isnot(None))
        .distinct()
        .all()
    )
    return {"categories": [c[0] for c in categories]}


@router.get(
    "/{signature_id}",
    response_model=SignatureResponse,
    summary="Get signature by ID",
    description="Retrieve a specific signature by its ID.",
)
def get_signature(signature_id: str, db: Session = Depends(get_database)):
    """
    Get a specific signature by ID.

    Args:
        signature_id: Unique signature identifier

    Returns:
        Signature details

    Raises:
        404: Signature not found
    """
    signature = db.query(Signature).filter(Signature.id == signature_id).first()
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature with ID {signature_id} not found",
        )
    return SignatureResponse.model_validate(signature)


@router.post(
    "/",
    response_model=SignatureResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create signature",
    description="Create a new detection signature.",
)
def create_signature(
    signature_data: SignatureCreate, db: Session = Depends(get_database)
):
    """
    Create a new detection signature.

    Args:
        signature_data: Signature definition

    Returns:
        Created signature

    Raises:
        400: Signature name already exists
    """
    # Check for duplicate name
    existing = db.query(Signature).filter(Signature.name == signature_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature with name '{signature_data.name}' already exists",
        )

    # Create signature
    signature = Signature(
        name=signature_data.name,
        description=signature_data.description,
        protocol=ProtocolType(signature_data.protocol.value),
        source_ip=signature_data.source_ip,
        source_port=signature_data.source_port,
        dest_ip=signature_data.dest_ip,
        dest_port=signature_data.dest_port,
        pattern=signature_data.pattern,
        severity=SeverityLevel(signature_data.severity.value),
        enabled=signature_data.enabled,
        category=signature_data.category,
        reference=signature_data.reference,
    )

    db.add(signature)
    db.commit()
    db.refresh(signature)

    ids_logger.info(f"Signature created: {signature.name}")

    # Trigger signature reload in detection engine
    _reload_signatures_if_running()

    return SignatureResponse.model_validate(signature)


@router.put(
    "/{signature_id}",
    response_model=SignatureResponse,
    summary="Update signature",
    description="Update an existing signature.",
)
def update_signature(
    signature_id: str,
    signature_data: SignatureUpdate,
    db: Session = Depends(get_database),
):
    """
    Update an existing signature.

    Args:
        signature_id: Signature to update
        signature_data: Updated fields (only provided fields are updated)

    Returns:
        Updated signature

    Raises:
        404: Signature not found
        400: Duplicate name
    """
    signature = db.query(Signature).filter(Signature.id == signature_id).first()
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature with ID {signature_id} not found",
        )

    # Check for duplicate name if name is being changed
    update_data = signature_data.model_dump(exclude_unset=True)
    if "name" in update_data and update_data["name"] != signature.name:
        existing = (
            db.query(Signature).filter(Signature.name == update_data["name"]).first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Signature with name '{update_data['name']}' already exists",
            )

    # Update fields
    for field, value in update_data.items():
        if field == "protocol" and value:
            value = ProtocolType(value.value if hasattr(value, "value") else value)
        elif field == "severity" and value:
            value = SeverityLevel(value.value if hasattr(value, "value") else value)
        setattr(signature, field, value)

    db.commit()
    db.refresh(signature)

    ids_logger.info(f"Signature updated: {signature.name}")

    # Trigger signature reload
    _reload_signatures_if_running()

    return SignatureResponse.model_validate(signature)


@router.delete(
    "/{signature_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete signature",
    description="Delete a signature.",
)
def delete_signature(signature_id: str, db: Session = Depends(get_database)):
    """
    Delete a signature.

    This will also delete all associated alerts (cascade).

    Args:
        signature_id: Signature to delete

    Raises:
        404: Signature not found
    """
    signature = db.query(Signature).filter(Signature.id == signature_id).first()
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature with ID {signature_id} not found",
        )

    name = signature.name
    db.delete(signature)
    db.commit()

    ids_logger.info(f"Signature deleted: {name}")

    # Trigger signature reload
    _reload_signatures_if_running()


@router.post(
    "/{signature_id}/toggle",
    response_model=SignatureResponse,
    summary="Toggle signature",
    description="Enable or disable a signature.",
)
def toggle_signature(signature_id: str, db: Session = Depends(get_database)):
    """
    Toggle a signature's enabled status.

    Args:
        signature_id: Signature to toggle

    Returns:
        Updated signature

    Raises:
        404: Signature not found
    """
    signature = db.query(Signature).filter(Signature.id == signature_id).first()
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature with ID {signature_id} not found",
        )

    signature.enabled = not signature.enabled  # type: ignore
    db.commit()
    db.refresh(signature)

    status_str = "enabled" if signature.enabled else "disabled"  # type: ignore
    ids_logger.info(f"Signature {status_str}: {signature.name}")

    # Trigger signature reload
    _reload_signatures_if_running()

    return SignatureResponse.model_validate(signature)


def _reload_signatures_if_running():
    """Reload signatures in detection engine if running."""
    engine = get_detector()
    if engine.is_running:
        engine.reload_signatures()
