CYAN    = \033[0;36m
GREEN   = \033[0;32m
YELLOW  = \033[0;33m
RESET   = \033[0m

.PHONY: check format commit install

default: check

check:
	@echo "$(CYAN)--- Running ruff import sorting checks (I)... ---$(RESET)"
	@ruff check --select I .
	@echo "$(CYAN)--- Running all ruff checks... ---$(RESET)"
	@ruff check .
	@echo "$(CYAN)--- Running pyright type checks... ---$(RESET)"
	@pyright
	@echo "$(GREEN)✅ All checks passed!$(RESET)"

format:
	@echo "$(CYAN)--- Fixing ruff import sorting (I)... ---$(RESET)"
	@ruff check --select I --fix .
	@echo "$(CYAN)--- Formatting code with ruff... ---$(RESET)"
	@ruff format .
	@echo "$(GREEN)✅ Code formatted!$(RESET)"

test:
	@echo "$(CYAN)--- Testing... ---$(RESET)"
	@pytest beelogin
	@echo "$(GREEN)✅ Pass!$(RESET)"

commit:
	@echo "$(YELLOW)--- Running pre-commit checks... ---$(RESET)"
	@$(MAKE) check
	@$(MAKE) test
	@echo "$(GREEN)--- Checks passed, proceeding with commit... ---$(RESET)"
	@git commit
