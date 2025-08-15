#!/bin/bash

# Debug script for flag-based module gating system
# This helps instructors and students debug the file-based flag tracking

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FLAG_DIR="/tmp/flag_progress"

usage() {
    echo "Flag Management Debug Tool"
    echo ""
    echo "Usage: $0 {status|unlock MODULE_NUM|reset|test}"
    echo ""
    echo "Commands:"
    echo "  status      - Show current progress and flag files"
    echo "  unlock N    - Manually unlock module N (2 or 3)"
    echo "  reset       - Clear all progress (unlock Module 1 only)"
    echo "  test        - Test the flag system with sample flags"
    echo ""
    echo "Examples:"
    echo "  $0 status                 # Check current progress"
    echo "  $0 unlock 2              # Manually unlock Module 2"
    echo "  $0 reset                 # Reset all progress"
}

show_status() {
    echo -e "${YELLOW}Flag Progress Status:${NC}"
    echo "===================="
    
    if [ -d "$FLAG_DIR" ]; then
        echo -e "Flag directory: ${GREEN}$FLAG_DIR${NC} (exists)"
        
        # Check each module
        echo ""
        echo "Module Status:"
        echo "  Module 1: ✅ Always unlocked"
        
        if [ -f "$FLAG_DIR/module2_unlocked.txt" ]; then
            echo -e "  Module 2: ${GREEN}✅ Unlocked${NC}"
            echo "    File: $FLAG_DIR/module2_unlocked.txt"
            echo "    Content: $(cat "$FLAG_DIR/module2_unlocked.txt" 2>/dev/null)"
        else
            echo -e "  Module 2: ${RED}🔒 Locked${NC}"
        fi
        
        if [ -f "$FLAG_DIR/module3_unlocked.txt" ]; then
            echo -e "  Module 3: ${GREEN}✅ Unlocked${NC}"
            echo "    File: $FLAG_DIR/module3_unlocked.txt"
            echo "    Content: $(cat "$FLAG_DIR/module3_unlocked.txt" 2>/dev/null)"
        else
            echo -e "  Module 3: ${RED}🔒 Locked${NC}"
        fi
        
        echo ""
        echo "All files in $FLAG_DIR:"
        ls -la "$FLAG_DIR/" 2>/dev/null || echo "  (empty directory)"
        
    else
        echo -e "Flag directory: ${RED}$FLAG_DIR${NC} (does not exist)"
        echo "This means no modules have been unlocked yet."
    fi
}

unlock_module() {
    local module_num="$1"
    
    if [ -z "$module_num" ]; then
        echo -e "${RED}Error: Module number required${NC}"
        echo "Usage: $0 unlock MODULE_NUM"
        return 1
    fi
    
    if [ "$module_num" != "2" ] && [ "$module_num" != "3" ]; then
        echo -e "${RED}Error: Only modules 2 and 3 can be unlocked${NC}"
        echo "Module 1 is always unlocked, Module 4 doesn't require flags"
        return 1
    fi
    
    # Create directory if it doesn't exist
    mkdir -p "$FLAG_DIR"
    
    # Create unlock file
    echo "Module $module_num unlocked manually at $(date)" > "$FLAG_DIR/module${module_num}_unlocked.txt"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Module $module_num unlocked successfully${NC}"
        echo "Created: $FLAG_DIR/module${module_num}_unlocked.txt"
    else
        echo -e "${RED}✗ Failed to unlock Module $module_num${NC}"
        return 1
    fi
}

reset_progress() {
    echo -e "${YELLOW}Resetting all flag progress...${NC}"
    
    if [ -d "$FLAG_DIR" ]; then
        rm -rf "$FLAG_DIR"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Progress reset successfully${NC}"
            echo "All modules are now locked (except Module 1 which is always unlocked)"
        else
            echo -e "${RED}✗ Failed to reset progress${NC}"
            echo "You may need to manually delete: $FLAG_DIR"
            return 1
        fi
    else
        echo -e "${YELLOW}ℹ No progress to reset${NC}"
        echo "Flag directory doesn't exist"
    fi
}

test_flags() {
    echo -e "${YELLOW}Testing flag system...${NC}"
    echo ""
    
    # Show current environment flags
    echo "Environment flag configuration:"
    echo "  FLAG1: ${FLAG1:-'(not set - will use default)'}"
    echo "  FLAG2: ${FLAG2:-'(not set - will use default)'}"
    echo ""
    
    # Test URL (assumes local development)
    BASE_URL="http://localhost:8080"
    
    echo "Test commands you can run:"
    echo ""
    echo "1. Check progress:"
    echo "   curl $BASE_URL/progress"
    echo ""
    echo "2. Submit flag1 to unlock Module 2:"
    echo "   curl -X POST $BASE_URL/submit-flag -d 'flag=flag{dev_bucket_found}'"
    echo ""
    echo "3. Submit flag2 to unlock Module 3:"
    echo "   curl -X POST $BASE_URL/submit-flag -d 'flag=flag{terraform_state_accessed}'"
    echo ""
    echo "4. Try accessing locked Module 2:"
    echo "   curl $BASE_URL/status"
    echo ""
    echo "5. Try accessing locked Module 3:"
    echo "   curl $BASE_URL/monitoring"
    echo ""
    echo -e "${YELLOW}Note: These assume the Flask app is running locally on port 8080${NC}"
}

# Main script logic
case "$1" in
    status|s)
        show_status
        ;;
    unlock|u)
        unlock_module "$2"
        ;;
    reset|r)
        reset_progress
        ;;
    test|t)
        test_flags
        ;;
    help|h|--help)
        usage
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        usage
        exit 1
        ;;
esac