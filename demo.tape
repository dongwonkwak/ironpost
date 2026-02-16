Output docs/demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 800
Set Theme "Molokai"
Set TypingSpeed 50ms

# Step 1: 서비스 상태 확인
Type "echo '=== Ironpost Demo: Unified Security Monitoring ==='"
Enter
Sleep 1.5s

Type "docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml ps --format 'table {{.Name}}\t{{.Status}}'"
Enter
Sleep 3s

# Step 2: 실시간 보안 이벤트 모니터링
Type "echo ''"
Enter
Type "echo '=== Live Security Events ==='"
Enter
Sleep 1s

Type "docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml logs --tail=0 -f ironpost 2>&1 | grep --line-buffered -E 'alert_id|severity|rule_id|listening|Received|container guard' | head -20"
Enter
Sleep 15s

# Step 3: 완료
Ctrl+C
Sleep 0.5s
Type "echo ''"
Enter
Type "echo '=== Demo complete. See docs/demo.md for full guide ==='"
Enter
Sleep 2s
