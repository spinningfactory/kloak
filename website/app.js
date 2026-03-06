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
 * Handle form submission via Formspree AJAX
 */
const demoForm = document.getElementById('demo-form');
const formStatus = document.getElementById('form-status');

if (demoForm) {
    demoForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const submitBtn = demoForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;

        // Disable button while submitting
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>Sending...</span>';

        const data = new FormData(demoForm);

        try {
            const response = await fetch(demoForm.action, {
                method: demoForm.method,
                body: data,
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (response.ok) {
                // Success UI
                formStatus.style.display = 'block';
                formStatus.style.backgroundColor = 'rgba(0, 191, 165, 0.1)';
                formStatus.style.color = '#00BFA5';
                formStatus.style.border = '1px solid #00BFA5';
                formStatus.textContent = 'Demo request sent successfully! We will be in touch soon.';
                demoForm.reset();
            } else {
                // Server Error UI
                let errorMessage = 'Oops! There was a problem submitting your form.';
                const result = await response.json();
                if (Object.hasOwn(result, 'errors')) {
                    errorMessage = result.errors.map(error => error.message).join(', ');
                }

                formStatus.style.display = 'block';
                formStatus.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
                formStatus.style.color = '#ef4444';
                formStatus.style.border = '1px solid #ef4444';
                formStatus.textContent = errorMessage;
            }
        } catch (error) {
            // Network Error UI
            formStatus.style.display = 'block';
            formStatus.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
            formStatus.style.color = '#ef4444';
            formStatus.style.border = '1px solid #ef4444';
            formStatus.textContent = 'Oops! There was a network error fulfilling your request.';
        } finally {
            // Re-enable button
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnText;

            // Hide status message after 8 seconds
            setTimeout(() => {
                formStatus.style.display = 'none';
            }, 8000);
        }
    });
}
