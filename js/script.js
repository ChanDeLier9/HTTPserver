// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    console.log('博客网站已加载完成');
    
    // 添加平滑滚动效果
    const navLinks = document.querySelectorAll('nav a[href^="#"]');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // 添加文章卡片的点击效果
    const postCards = document.querySelectorAll('.post-card');
    postCards.forEach(card => {
        card.addEventListener('click', function() {
            // 添加点击动画效果
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    });
    
    // 添加页面加载动画
    const heroContent = document.querySelector('.hero-content');
    if (heroContent) {
        heroContent.style.opacity = '0';
        heroContent.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            heroContent.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
            heroContent.style.opacity = '1';
            heroContent.style.transform = 'translateY(0)';
        }, 100);
    }
    
    // 添加滚动时的导航栏效果
    let lastScrollTop = 0;
    window.addEventListener('scroll', function() {
        const header = document.querySelector('header');
        const currentScrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        if (currentScrollTop > lastScrollTop && currentScrollTop > 100) {
            // 向下滚动
            header.style.transform = 'translateY(-100%)';
        } else {
            // 向上滚动
            header.style.transform = 'translateY(0)';
        }
        
        lastScrollTop = currentScrollTop;
    });
    
    // 添加图片加载错误处理
    const images = document.querySelectorAll('img');
    images.forEach(img => {
        img.addEventListener('error', function() {
            this.style.display = 'none';
            console.warn('图片加载失败:', this.src);
        });
    });
    
    // 添加当前时间显示
    function updateTime() {
        const now = new Date();
        const timeString = now.toLocaleString('zh-CN');
        
        // 可以在页脚或其他地方显示时间
        const footer = document.querySelector('.footer-content p');
        if (footer) {
            footer.innerHTML = `&copy; 2024 我的博客. 由C语言HTTP服务器提供支持. | 当前时间: ${timeString}`;
        }
    }
    
    // 每秒更新时间
    setInterval(updateTime, 1000);
    updateTime(); // 立即执行一次
    
    // 添加控制台欢迎信息
    console.log('%c欢迎访问我的博客！', 'color: #667eea; font-size: 20px; font-weight: bold;');
    console.log('%c这是一个由C语言HTTP服务器提供服务的网站', 'color: #666; font-size: 14px;');
}); 
