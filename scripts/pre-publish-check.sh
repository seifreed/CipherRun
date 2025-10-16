#!/bin/bash
# Pre-Publish Checklist Script for CipherRun
# Verifica que todo esté listo antes de publicar en crates.io

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CipherRun - Pre-Publish Checklist           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print status
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 1. Check code formatting
echo -e "${BLUE}[1/10]${NC} Verificando formato de código..."
if cargo fmt --check > /dev/null 2>&1; then
    check_pass "Código formateado correctamente"
else
    check_fail "Código necesita formateo. Ejecuta: cargo fmt"
fi

# 2. Check clippy warnings
echo -e "${BLUE}[2/10]${NC} Verificando clippy..."
CLIPPY_WARNINGS=$(cargo clippy --release 2>&1 | grep -c "warning" || true)
if [ "$CLIPPY_WARNINGS" -eq 0 ]; then
    check_pass "Sin warnings de clippy"
else
    check_fail "Clippy encontró $CLIPPY_WARNINGS warning(s). Ejecuta: cargo clippy"
fi

# 3. Run tests
echo -e "${BLUE}[3/10]${NC} Ejecutando tests..."
if cargo test --lib --quiet > /dev/null 2>&1; then
    TEST_RESULTS=$(cargo test --lib 2>&1 | grep "test result" || true)
    check_pass "Tests: $TEST_RESULTS"
else
    check_fail "Tests fallaron. Ejecuta: cargo test"
fi

# 4. Check compilation
echo -e "${BLUE}[4/10]${NC} Verificando compilación release..."
if cargo build --release --quiet > /dev/null 2>&1; then
    check_pass "Compilación exitosa"
else
    check_fail "Compilación falló. Ejecuta: cargo build --release"
fi

# 5. Check Cargo.toml metadata
echo -e "${BLUE}[5/10]${NC} Verificando metadata en Cargo.toml..."
MISSING_FIELDS=()

if ! grep -q "^description = " Cargo.toml; then
    MISSING_FIELDS+=("description")
fi
if ! grep -q "^license = " Cargo.toml; then
    MISSING_FIELDS+=("license")
fi
if ! grep -q "^repository = " Cargo.toml; then
    MISSING_FIELDS+=("repository")
fi
if ! grep -q "^keywords = " Cargo.toml; then
    MISSING_FIELDS+=("keywords")
fi
if ! grep -q "^categories = " Cargo.toml; then
    MISSING_FIELDS+=("categories")
fi

if [ ${#MISSING_FIELDS[@]} -eq 0 ]; then
    check_pass "Metadata completa en Cargo.toml"
else
    check_fail "Faltan campos en Cargo.toml: ${MISSING_FIELDS[*]}"
fi

# 6. Check README.md exists
echo -e "${BLUE}[6/10]${NC} Verificando README.md..."
if [ -f "README.md" ]; then
    README_SIZE=$(wc -c < README.md)
    check_pass "README.md existe (${README_SIZE} bytes)"
else
    check_fail "README.md no encontrado"
fi

# 7. Check LICENSE exists
echo -e "${BLUE}[7/10]${NC} Verificando LICENSE..."
if [ -f "LICENSE" ]; then
    check_pass "LICENSE existe"
else
    check_fail "LICENSE no encontrado"
fi

# 8. Package and check size
echo -e "${BLUE}[8/10]${NC} Empaquetando y verificando tamaño..."
if cargo package --quiet 2>&1 | grep -q "Packaged"; then
    CRATE_FILE=$(ls -t target/package/cipherrun-*.crate | head -1)
    SIZE_KB=$(du -k "$CRATE_FILE" | cut -f1)
    SIZE_MB=$(echo "scale=2; $SIZE_KB / 1024" | bc)

    if [ "$SIZE_KB" -lt 10240 ]; then
        check_pass "Tamaño del paquete: ${SIZE_MB}MB (límite: 10MB)"
    else
        check_fail "Paquete demasiado grande: ${SIZE_MB}MB (límite: 10MB)"
    fi
else
    check_fail "Empaquetado falló. Ejecuta: cargo package"
fi

# 9. Check documentation builds
echo -e "${BLUE}[9/10]${NC} Verificando documentación..."
if cargo doc --no-deps --quiet > /dev/null 2>&1; then
    check_pass "Documentación generada correctamente"
else
    check_warn "Documentación generó warnings (no crítico)"
fi

# 10. Verify package contents
echo -e "${BLUE}[10/10]${NC} Verificando contenidos del paquete..."
PACKAGE_FILES=$(cargo package --list 2>&1)
REQUIRED_FILES=("README.md" "LICENSE" "Cargo.toml" "src/main.rs")
MISSING_REQUIRED=()

for file in "${REQUIRED_FILES[@]}"; do
    if ! echo "$PACKAGE_FILES" | grep -q "$file"; then
        MISSING_REQUIRED+=("$file")
    fi
done

if [ ${#MISSING_REQUIRED[@]} -eq 0 ]; then
    check_pass "Archivos requeridos incluidos"
else
    check_fail "Faltan archivos requeridos: ${MISSING_REQUIRED[*]}"
fi

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✓ Todos los checks pasaron exitosamente!    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Siguiente paso:${NC}"
echo -e "  1. Revisa el contenido: ${YELLOW}cargo package --list${NC}"
echo -e "  2. Haz un dry-run:      ${YELLOW}cargo publish --dry-run${NC}"
echo -e "  3. Publica:             ${YELLOW}cargo publish${NC}"
echo ""
echo -e "${YELLOW}⚠ Recuerda:${NC} No puedes eliminar o modificar una versión una vez publicada"
echo ""
