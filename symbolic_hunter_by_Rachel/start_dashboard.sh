#!/bin/bash
# Start SymbolicHunter Web Dashboard

echo "🔍 Starting SymbolicHunter Web Dashboard..."
echo ""

# Check if Flask is installed
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "📦 Installing required packages..."
    pip install -r requirements.txt
fi

# Create necessary directories
mkdir -p templates uploads output

# Start the server
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       SymbolicHunter Web Dashboard                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Opening dashboard at http://localhost:5000"
echo "📊 Interactive interface ready"
echo "🔍 Real-time analysis monitoring"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Open browser (optional)
sleep 2
command -v xdg-open > /dev/null && xdg-open http://localhost:5000 &
command -v open > /dev/null && open http://localhost:5000 &

# Start Flask app
python3 web_dashboard.py
