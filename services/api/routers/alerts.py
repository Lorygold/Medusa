from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from models.alert import Alert, AlertOut, AlertFalcoInput
from db.session import get_db

router = APIRouter()


@router.post("/falco")
async def receive_falco_alert(
    alert_data: AlertFalcoInput,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Receive an alert from Falco webhook.
    
    Falco sends a POST request to this endpoint with alert details.
    The alert is normalized and persisted to PostgreSQL.
    """
    try:
        # Extract container_name and image from output_fields if available
        container_name = None
        image = None
        
        if alert_data.output_fields:
            container_name = alert_data.output_fields.get("container_name")
            image = alert_data.output_fields.get("container_image")
        
        # Create Alert record
        new_alert = Alert(
            rule=alert_data.rule,
            priority=alert_data.priority,
            output=alert_data.output,
            container_name=container_name,
            image=image,
            tags=alert_data.tags or [],
            raw_event=alert_data.dict(),
        )
        
        db.add(new_alert)
        await db.commit()
        await db.refresh(new_alert)
        
        return {
            "status": "received",
            "alert_id": str(new_alert.id),
            "rule": new_alert.rule,
            "priority": new_alert.priority,
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to persist alert: {str(e)}")


@router.get("/")
async def get_alerts(
    priority: Optional[str] = Query(
        None,
        description="Filter by priority: debug, info, notice, warning, error, critical",
    ),
    container: Optional[str] = Query(
        None,
        description="Filter by container_name (exact match)",
    ),
    since: Optional[str] = Query(
        None,
        description="Filter by received_at (ISO 8601 datetime, return alerts after this time)",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Number of results per page (1-1000, default 100)",
    ),
    offset: int = Query(
        0,
        ge=0,
        description="Number of results to skip (default 0)",
    ),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all alerts with optional filtering and pagination.
    
    Query Parameters:
    - priority: Filter by Falco alert severity
    - container: Filter by container name
    - since: Return alerts after this ISO 8601 datetime
    - limit: Results per page (1-1000, default 100)
    - offset: Pagination offset (default 0)
    
    Returns paginated list of alerts sorted by received_at (newest first).
    """
    try:
        # Build query
        query = select(Alert).order_by(Alert.received_at.desc())
        
        # Apply filters
        if priority:
            query = query.where(Alert.priority == priority)
        
        if container:
            query = query.where(Alert.container_name == container)
        
        if since:
            try:
                # Parse ISO 8601 datetime
                parsed_since = datetime.fromisoformat(since)
                query = query.where(Alert.received_at > parsed_since)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid 'since' parameter. Expected ISO 8601 format (e.g., 2024-01-15T10:30:00)",
                )
        
        # Apply pagination
        query = query.limit(limit).offset(offset)
        
        # Execute query
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        # Convert to response schemas
        alert_list = [AlertOut.from_orm(alert) for alert in alerts]
        
        return {
            "data": alert_list,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "count": len(alert_list),
            },
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve alerts: {str(e)}",
        )


@router.get("/{alert_id}")
async def get_alert_detail(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """
    Get a single alert by ID.
    """
    try:
        # Parse UUID
        try:
            uuid_obj = UUID(alert_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid alert_id. Expected valid UUID.",
            )
        
        # Query alert
        query = select(Alert).where(Alert.id == uuid_obj)
        result = await db.execute(query)
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(
                status_code=404,
                detail=f"Alert with ID {alert_id} not found.",
            )
        
        return AlertOut.from_orm(alert)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve alert: {str(e)}",
        )