# Start backend (http://localhost:8000) and frontend (http://localhost:5173) for development.
$root = Split-Path -Parent $PSScriptRoot
Start-Process -FilePath "$root\backend\.venv\Scripts\python.exe" -ArgumentList "-m","uvicorn","app.main:app","--reload","--port","8000" -WorkingDirectory "$root\backend"
Start-Process -FilePath "npm.cmd" -ArgumentList "run","dev" -WorkingDirectory "$root\frontend"
Write-Host "Backend: http://localhost:8000/docs   Frontend: http://localhost:5173"
