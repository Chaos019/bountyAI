from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/bounty", tags=["Health"])
async def health_check():
    return JSONResponse(content={"status": "running", "version": "3.0.0"})
