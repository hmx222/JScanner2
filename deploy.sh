#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$HOME/jscanner2"
VENV_DIR="$PROJECT_DIR/venv"
MODEL_NAME="hf-mirror.com/wqerrewetw/DistilQwen2.5-7B-Instruct-GGUF:Q4_K_M"
USE_GPU=false

check_root() {
    [ "$(id -u)" != "0" ] && echo -e "${RED}❌ 请用sudo运行: sudo $0${NC}" && exit 1
    echo -e "${GREEN}✅ root权限检查通过${NC}"
}

# 优化后的Python环境检查函数
fix_ubuntu_python() {
    echo -e "${BLUE}🔧 检查和修复Python环境...${NC}"

    # 检查当前Python版本
    echo -e "${BLUE}🔍 检查当前Python版本...${NC}"
    if command -v python3 >/dev/null 2>&1; then
        current_python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
        echo -e "${GREEN}✅ 当前Python版本: ${current_python_version}${NC}"

        # 检查版本是否 >= 3.8
        if (( $(echo "$current_python_version >= 3.8" | bc -l) )); then
            echo -e "${GREEN}✅ Python版本 ${current_python_version} 满足要求，跳过安装步骤${NC}"

            # 确保venv和dev包已安装
            echo -e "${YELLOW}💡 检查必要的Python组件...${NC}"
            missing_components=0

            if ! python3 -c "import venv" >/dev/null 2>&1; then
                echo -e "${YELLOW}⚠️  venv模块未安装，正在安装...${NC}"
                apt-get install -y python3-venv
                missing_components=1
            fi

            if ! python3-config --includes >/dev/null 2>&1; then
                echo -e "${YELLOW}⚠️  python3-dev未安装，正在安装...${NC}"
                apt-get install -y python3-dev
                missing_components=1
            fi

            if [ $missing_components -eq 0 ]; then
                echo -e "${GREEN}✅ 所有必要组件已安装${NC}"
            fi

            # 安装pip（如果需要）
            if ! command -v pip3 >/dev/null 2>&1; then
                echo -e "${YELLOW}⚠️  pip未安装，正在安装...${NC}"
                apt-get install -y python3-pip
            fi

            echo -e "${GREEN}✅ Python环境检查完成${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️  Python版本 ${current_python_version} 低于要求 (需要 >= 3.8)，继续安装Python 3.10${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  未找到Python3，需要完整安装${NC}"
    fi

    # 如果版本不满足要求，执行完整修复流程
    echo -e "${BLUE}🔧 执行完整Python环境修复...${NC}"

    # 更新系统
    apt-get update
    apt-get upgrade -y

    # 安装基础工具
    apt-get install -y software-properties-common curl wget git build-essential

    # 检查Ubuntu版本
    . /etc/os-release
    echo -e "${GREEN}✅ 系统版本: $PRETTY_NAME${NC}"

    # 启用universe仓库
    echo -e "${YELLOW}💡 启用universe仓库...${NC}"
    add-apt-repository universe -y

    # 添加deadsnakes PPA
    echo -e "${YELLOW}💡 添加Python 3.10 PPA源...${NC}"
    add-apt-repository ppa:deadsnakes/ppa -y

    # 重新更新
    apt-get update

    # 安装Python 3.10
    echo -e "${YELLOW}📦 安装Python 3.10...${NC}"

    # 尝试安装主要包
    if ! apt-get install -y python3.10 python3.10-venv python3.10-dev; then
        echo -e "${YELLOW}⚠️  主要包安装失败，尝试分步安装...${NC}"

        # 分步安装
        apt-get install -y python3.10 || echo -e "${YELLOW}⚠️  python3.10安装失败，继续...${NC}"
        apt-get install -y python3.10-venv || echo -e "${YELLOW}⚠️  python3.10-venv安装失败，继续...${NC}"
        apt-get install -y python3.10-dev || echo -e "${YELLOW}⚠️  python3.10-dev安装失败，继续...${NC}"
    fi

    # 安装pip
    apt-get install -y python3-pip

    # 验证安装
    if command -v python3.10 >/dev/null 2>&1; then
        installed_version=$(python3.10 --version 2>&1 | cut -d' ' -f2)
        echo -e "${GREEN}✅ Python 3.10安装成功: ${installed_version}${NC}"
    else
        echo -e "${RED}❌ Python 3.10安装失败，尝试使用python3${NC}"
        # 确保有python3
        apt-get install -y python3 python3-venv python3-dev
        echo -e "${YELLOW}💡 使用python3作为替代${NC}"
    fi

    echo -e "${GREEN}✅ Python环境修复完成${NC}"
}

detect_gpu() {
    echo -e "${BLUE}🎮 检测GPU...${NC}"
    if command -v lspci >/dev/null 2>&1; then
        if lspci | grep -i nvidia >/dev/null 2>&1; then
            USE_GPU=true
            echo -e "${GREEN}✅ 检测到NVIDIA GPU${NC}"
        else
            echo -e "${YELLOW}⚠️  未检测到NVIDIA GPU，使用CPU模式${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  未安装lspci，安装pciutils...${NC}"
        apt-get install -y pciutils
        if lspci | grep -i nvidia >/dev/null 2>&1; then
            USE_GPU=true
            echo -e "${GREEN}✅ 检测到NVIDIA GPU${NC}"
        else
            echo -e "${YELLOW}⚠️  未检测到NVIDIA GPU，使用CPU模式${NC}"
        fi
    fi
}

install_deps() {
    echo -e "${BLUE}📦 安装系统依赖...${NC}"

    # 安装图形库和多媒体依赖
    apt-get install -y \
        libgl1 \
        libsm6 \
        libxrender1 \
        libxext6 \
        ffmpeg \
        xvfb \
        libgl1-mesa-glx \
        libgbm1 \
        libasound2 \
        libgl1-mesa-dev \
        libgles2-mesa-dev \
        libegl1-mesa-dev \
        libglu1-mesa-dev

    # 安装构建工具
    apt-get install -y build-essential

    echo -e "${GREEN}✅ 系统依赖安装完成${NC}"
}


setup_project() {
    echo -e "${BLUE}🐍 设置Python环境...${NC}"
    mkdir -p "$PROJECT_DIR"
    cd "$PROJECT_DIR"

    # 克隆项目
    if [ ! -d .git ]; then
        echo -e "${YELLOW}⚠️  克隆项目仓库...${NC}"
        git clone https://github.com/hmx222/JScanner2 .
    else
        echo -e "${YELLOW}🔄 更新项目代码...${NC}"
        git pull
    fi

    # 检查Python版本
    python_cmd="python3"
    if command -v python3.10 >/dev/null 2>&1; then
        python_cmd="python3.10"
        echo -e "${GREEN}✅ 使用Python 3.10${NC}"
    else
        echo -e "${YELLOW}⚠️  使用系统默认python3${NC}"
    fi

    # 创建虚拟环境
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}🏗️  创建虚拟环境 (${python_cmd})${NC}"
        "$python_cmd" -m venv "$VENV_DIR"
    fi

    # 激活虚拟环境
    source "$VENV_DIR/bin/activate"

    # 安装依赖
    echo -e "${YELLOW}⏫ 升级pip...${NC}"
    pip install --upgrade pip

    echo -e "${YELLOW}📋 安装Python依赖...${NC}"
    if [ ! -f requirements.txt ]; then
        pip install scrapy playwright beautifulsoup4 selenium requests aiohttp asyncio jieba simhash
        pip freeze > requirements.txt
    fi

    pip install -r requirements.txt

    # 安装PyTorch
    echo -e "${YELLOW}🔥 安装PyTorch...${NC}"
    if [ "$USE_GPU" = true ]; then
        echo -e "${YELLOW}💡 安装GPU版本PyTorch...${NC}"
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
    else
        echo -e "${YELLOW}💡 安装CPU版本PyTorch...${NC}"
        pip install torch torchvision torchaudio
    fi

    # 安装Playwright
    echo -e "${YELLOW}🌐 安装Playwright...${NC}"
    pip install playwright
    playwright install --with-deps chromium

    echo -e "${GREEN}✅ Python环境设置完成${NC}"
}

create_run_script() {
    echo -e "${BLUE}📝 创建运行脚本...${NC}"
    cat > "$PROJECT_DIR/run_scan.sh" << 'EOF'
#!/bin/bash
set -e
echo "🚀 启动 JScanner2..."
source venv/bin/activate
cd ~/jscanner2
python main.py "$@"
EOF
    chmod +x "$PROJECT_DIR/run_scan.sh"
    echo -e "${GREEN}✅ 运行脚本创建完成${NC}"
}

main() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}🚀 智能Ubuntu部署脚本${NC}"
    echo -e "${GREEN}========================================${NC}"

    check_root
    fix_ubuntu_python
    detect_gpu
    install_deps
    setup_project
    create_run_script

    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}🎉 部署完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "📋 项目目录: $PROJECT_DIR"
    echo -e "🔧 使用方法:"
    echo -e "cd $PROJECT_DIR"
    echo -e "./run_scan.sh -u \"https://example.com\" -H 3 -o -g -s 0.8"
    echo -e "${GREEN}========================================${NC}"
}

main "$@"