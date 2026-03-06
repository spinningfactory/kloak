/**
 * Kloak Website JavaScript
 * Handles interactivity and animations
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    initMobileMenu();
    initScrollAnimations();
});

/**
 * Navbar scroll effect
 */
function initNavbar() {
    const navbar = document.getElementById('navbar');

    const handleScroll = () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll(); // Initial check
}

/**
 * Mobile menu toggle
 */
function initMobileMenu() {
    const toggle = document.getElementById('nav-toggle');
    const menu = document.getElementById('nav-menu');
    const links = menu.querySelectorAll('.nav-link');

    toggle.addEventListener('click', () => {
        menu.classList.toggle('active');
        toggle.classList.toggle('active');
    });

    // Close menu when clicking a link
    links.forEach(link => {
        link.addEventListener('click', () => {
            menu.classList.remove('active');
            toggle.classList.remove('active');
        });
    });
}


/**
 * Scroll-triggered animations using Intersection Observer
 */
function initScrollAnimations() {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe elements
    const animatedElements = document.querySelectorAll(
        '.feature-card, .step, .arch-diagram, .install-step'
    );

    animatedElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = `opacity 0.5s ease ${index * 0.1}s, transform 0.5s ease ${index * 0.1}s`;
        observer.observe(el);
    });
}

// Add CSS for animation
const style = document.createElement('style');
style.textContent = `
    .animate-in {
        opacity: 1 !important;
        transform: translateY(0) !important;
    }
`;
document.head.appendChild(style);

/**
 * Smooth scroll for anchor links
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const headerOffset = 80;
            const elementPosition = target.getBoundingClientRect().top;
            const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

            window.scrollTo({
                top: offsetPosition,
                behavior: 'smooth'
            });
        }
    });
});

/**
 * Handle form submission via mailto
 */
const demoForm = document.getElementById('demo-form');
if (demoForm) {
    demoForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const company = document.getElementById('company').value;
        const message = document.getElementById('message').value;

        const subject = encodeURIComponent(`Demo Request from ${name} at ${company}`);
        const body = encodeURIComponent(
            `Name: ${name}\n` +
            `Email: ${email}\n` +
            `Company: ${company}\n\n` +
            `Message:\n${message}`
        );

        window.location.href = `mailto:mailto@spinningfactory.io?subject=${subject}&body=${body}`;
    });
}
