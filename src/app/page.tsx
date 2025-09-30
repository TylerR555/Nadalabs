'use client';

import { useState, useEffect, ChangeEvent, FormEvent } from 'react';
import Image from 'next/image';
import Loader from '@/components/Loader';
import { AnimatedSection } from '@/hooks/useIntersectionObserver';

export default function Home() {
  const [isLoading, setIsLoading] = useState(true);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    message: '',
    marketingOptOut: false,
  });
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [feedback, setFeedback] = useState<
    | {
        type: 'success' | 'error';
        message: string;
      }
    | null
  >(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [captchaToken] = useState<string | null>(null);

  useEffect(() => {
    const handleScroll = () => {
      const scrollTop = window.scrollY;
      setIsScrolled(scrollTop > 10);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleInputChange = (
    event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value, type, checked } = event.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setValidationErrors([]);
    setFeedback(null);
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...formData,
          captchaToken,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        const errors = Array.isArray(data.errors) ? data.errors : undefined;
        if (errors?.length) {
          setValidationErrors(errors);
          setFeedback({
            type: 'error',
            message: 'Please review the highlighted issues and try again.',
          });
        } else if (data.error) {
          setFeedback({ type: 'error', message: data.error });
        } else {
          setFeedback({
            type: 'error',
            message: 'Something went wrong. Please try again later.',
          });
        }
        return;
      }

      setFeedback({
        type: 'success',
        message: 'Thanks for reaching out! We will be in touch soon.',
      });
      setFormData({
        firstName: '',
        lastName: '',
        email: '',
        phone: '',
        message: '',
        marketingOptOut: false,
      });
    } catch (error) {
      console.error('Failed to submit contact form', error);
      setFeedback({
        type: 'error',
        message: 'Unable to submit the form right now. Please try again later.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return <Loader onComplete={() => setIsLoading(false)} />;
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Sticky Header Menu */}
      <header className={`sticky top-0 z-50 h-[80px] md:h-[106px] transition-all duration-300 ${isScrolled ? 'bg-white/95 backdrop-blur-md shadow-xl' : 'bg-white/90 backdrop-blur-sm shadow-lg'} shadow-black/10`}>
        <div className="w-full h-full flex items-center justify-center px-4 md:px-6">
          <div className="w-full max-w-[1275px] h-full flex items-center justify-between">
            <div className="flex flex-col items-start">
              <Image
                src="/logo.png"
                alt="Logo"
                width={120}
                height={20}
                className="md:w-[167px] md:h-[27px]"
              />
              <p className="text-black font-semibold mt-1 text-[9px] md:text-[11px]">Simplifying Managed Services</p>
            </div>
            
            <nav className="hidden lg:flex items-center space-x-8 xl:space-x-12">
              <a href="#" className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-sm">
                Home
              </a>
              <a href="#" className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-sm">
                Company
              </a>
              <a href="#" className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-sm">
                Services
              </a>
              <a href="#" className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-sm">
                Resources
              </a>
              <a href="#" className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-sm">
                Contact Us
              </a>
            </nav>

            <a 
              className="hidden lg:block font-[family-name:var(--font-figtree)] rounded-full px-8 xl:px-16 py-2.5 transition-colors hover:opacity-90 text-sm xl:text-base"
              style={{
                backgroundColor: "var(--brand-yellow)",
                color: "#000"
              }}
              href="#"
            >
              Request a Demo
            </a>              {/* Mobile Menu Button */}
            <button 
              className="lg:hidden flex flex-col space-y-1"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            >
              <span className={`w-6 h-0.5 bg-foreground transition-transform ${isMobileMenuOpen ? 'rotate-45 translate-y-1.5' : ''}`}></span>
              <span className={`w-6 h-0.5 bg-foreground transition-opacity ${isMobileMenuOpen ? 'opacity-0' : ''}`}></span>
              <span className={`w-6 h-0.5 bg-foreground transition-transform ${isMobileMenuOpen ? '-rotate-45 -translate-y-1.5' : ''}`}></span>
            </button>
          </div>
        </div>
        
        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden absolute top-full left-0 right-0 bg-white shadow-lg border-t border-gray-200">
            <nav className="flex flex-col p-4 space-y-4">
              <a 
                href="#" 
                className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-base py-2"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Home
              </a>
              <a 
                href="#" 
                className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-base py-2"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Company
              </a>
              <a 
                href="#" 
                className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-base py-2"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Services
              </a>
              <a 
                href="#" 
                className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-base py-2"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Resources
              </a>
              <a 
                href="#" 
                className="text-foreground hover:text-blue-600 font-normal transition-colors font-[family-name:var(--font-poppins)] text-base py-2"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Contact Us
              </a>
              <a 
                className="font-[family-name:var(--font-figtree)] rounded-full px-6 py-2.5 transition-colors hover:opacity-90 text-center mt-4"
                style={{
                  backgroundColor: "var(--brand-yellow)",
                  color: "#000"
                }}
                href="#"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Request a Demo
              </a>
            </nav>
          </div>
        )}
      </header>{/* Hero Slider Section */}
      <AnimatedSection animation="fade-in-right" delay={200}>
        <section className="relative w-full h-[400px] md:h-[500px] lg:h-[620px] bg-white">
          {/* Image positioned relative to full section - Hidden on mobile */}
          <div className="hidden md:block absolute right-0 bottom-0 w-1/2 h-[400px] md:h-[450px] lg:h-[508px] overflow-hidden">
            <Image
              src="/slider_right_desk.png"
              alt="Slider Desktop"
              width={0}
              height={0}
              sizes="100vw"
              className="w-full h-auto object-contain object-bottom-left"
              style={{ minHeight: '100%', marginRight: '500px' }}
            />
          </div>
          
          {/* Boxed layout for content */}
          <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-full max-w-[1275px] h-full px-4 md:px-6">
            <div className="relative w-full h-full">
              {/* Left column for content */}
              <div className="absolute mt-10 left-0 top-0 w-full md:w-1/2 h-full flex flex-col justify-center md:justify-start md:items-end lg:items-start text-center md:text-left">
                <h1 
                  className="font-[family-name:var(--font-inter)] font-normal text-black leading-tight mb-6 md:mb-15 text-2xl md:text-4xl lg:text-5xl xl:text-[3.2rem]
				  md:text-text-left lg:text-left xl:text-left"
                  style={{ textTransform: "uppercase" }}
                >
                  NextGen<br />
                  Communications &<br />
                  Managed Services
                </h1>
                
                <p 
                  className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 mb-8 md:mb-15 leading-relaxed text-sm md:text-lg lg:text-xl xl:text-[1.3rem] max-w-lg md:max-w-none"
                >
                  Nadalabs takes the complexity out of business communications for Large-enterprises and<span className="hidden md:inline"><br /></span> resellers.
                </p>
                
                <div className="flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-4">
                  <a 
                    className="font-[family-name:var(--font-figtree)] rounded-full px-8 md:px-12 py-3 transition-colors hover:opacity-90 text-sm md:text-base whitespace-nowrap"
                    style={{
                      backgroundColor: "var(--brand-yellow)",
                      color: "#000"
                    }}
                    href="#"
                  >
                    Talk to a Expert
                  </a>
                  
                  <a 
                    className="w-12 h-12 rounded-full flex items-center justify-center transition-colors hover:opacity-90"
                    style={{
                      backgroundColor: "var(--brand-orange-light)",
                      border: "1px solid var(--brand-orange)",
                    }}
                    href="#"
                  >
                    <svg 
                      width="16" 
                      height="16" 
                      viewBox="0 0 16 16" 
                      fill="none"
                      style={{ color: "var(--brand-yellow)" }}
                    >
                      <path 
                        d="M3 2L13 8L3 14V2Z" 
                        fill="currentColor"
                      />
                    </svg>
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>      {/* Who We Are Section */}
      <AnimatedSection animation="fade-in-left" delay={100}>
        <section className="relative w-full py-12 md:py-20 bg-white">
          <div className="w-full flex items-center justify-center px-4 md:px-6">
            <div className="w-full max-w-[1275px] flex flex-col lg:flex-row lg:items-start lg:space-x-12 space-y-8 lg:space-y-0">
              {/* First column - 40% */}
              <div className="w-full lg:w-2/5 flex flex-col">
                <div 
                  className="inline-block w-fit rounded-full px-4 md:px-6 py-2 md:py-3 mb-6 md:mb-8"
                  style={{
                    backgroundColor: "var(--brand-orange-light)",
                    border: "1px solid var(--brand-orange)",
                    color: "var(--brand-orange)"
                  }}
                >
                  <span 
                    className="font-[family-name:var(--font-poppins)] font-normal text-sm md:text-base"
                  >
                    Who We Are
                  </span>
                </div>
                
                <h2 
                  className="font-[family-name:var(--font-inter)] font-normal text-black leading-tight text-2xl md:text-4xl lg:text-5xl"
                >
                  Streamline your entire network.
                </h2>
              </div>
              
              {/* Second column - 60% */}
              <div className="w-full lg:w-3/5 flex flex-col space-y-4 md:space-y-6">
                <p 
                  className="font-[family-name:var(--font-poppins)] font-semibold text-gray-800 leading-relaxed text-sm md:text-base"
                >
                  NadaLabs provides comprehensive, managed technology solutions to help businesses streamline their network to make communications, collaboration and connectivity simple and cost-effective.
                </p>
                
                <p 
                  className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed text-sm md:text-base"
                >
                  Business networks are complex by nature. Add in multiple locations and vendors, different ways of working, and evolving technology needs and the infrastructure can quickly get out of control. Without proper transparency, oversight, and expertise, companies end up relying on insufficient legacy systems, building out unsustainable networks, and overspending on services they don&apos;t need.
                </p>
                
                <p 
                  className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed mb-6 md:mb-8 text-sm md:text-base"
                >
                  Nadalabs can help you right-fit your technology to meet your current network needs and scale as you grow. Your network may be complex, but it doesn&apos;t have to be unmanageable. Let NadaLabs show you how.
                </p>
                
                <div className="mt-6 md:mt-8">
                  <a 
                    className="font-[family-name:var(--font-figtree)] rounded-full px-6 md:px-8 py-2.5 md:py-3 transition-colors hover:opacity-90 text-sm md:text-base"
                    style={{
                      backgroundColor: "var(--brand-yellow)",
                      color: "#000"
                    }}
                    href="#"
                  >
                    Talk to an Expert
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>      {/* Why Choose Us Section */}
      <AnimatedSection animation="fade-in-right" delay={150}>
        <section className="relative w-full px-4 md:px-6 lg:px-20 py-12 md:py-20" style={{backgroundColor: "#fff6db"}}>
          <div className="w-full flex items-center justify-center">
            <div className="w-full max-w-[1275px] flex flex-col items-center">
              {/* Section Header */}
              <div className="flex flex-col items-center mb-12 md:mb-16">
                <div 
                  className="inline-block w-fit rounded-full px-4 md:px-6 py-2 md:py-3 mb-6 md:mb-8"
                  style={{
                    backgroundColor: "var(--brand-orange-light)",
                    border: "1px solid var(--brand-orange)",
                    color: "var(--brand-orange)"
                  }}
                >
                  <span 
                    className="font-[family-name:var(--font-poppins)] font-normal text-sm md:text-base"
                  >
                    Why Choose Us
                  </span>
                </div>
                
                <h2 
                  className="font-[family-name:var(--font-inter)] font-normal text-black leading-tight text-center mb-4 md:mb-6 text-2xl md:text-4xl lg:text-5xl"
                >
                  NadaLabs Solutions
                </h2>
                
                <p 
                  className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-center leading-relaxed max-w-4xl text-sm md:text-base"
                >
                  Broad network expertise from a single provider. This is<br className="hidden md:block"/>what an intelligent infrastructure looks like.
                </p>
              </div>
              
              {/* Two Column List */}
              <div className="w-full flex flex-col lg:flex-row lg:pl-15 lg:items-start lg:space-x-12 space-y-8 lg:space-y-0">
                {/* Column 1 - NextGen Communications */}
                <div className="w-full lg:w-1/2 flex flex-col">
                  <h3 
                    className="font-[family-name:var(--font-inter)] font-normal text-black mb-4 md:mb-6 text-lg md:text-xl"
                  >
                    NextGen Communications
                  </h3>
                  
                  <ul className="space-y-3 mb-4 md:mb-6">
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/bubble.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        UCaaS
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/bubble.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Managed SIP
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/bubble.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        SIP Trunking
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/bubble.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Voice Enabled Teams
                      </span>
                    </li>
                  </ul>
                  
                  <p 
                    className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed text-sm md:text-base"
                  >
                    NextGen Communications providing communication and collaboration for businesses
                  </p>
                </div>
                
                {/* Column 2 - Managed Services */}
                <div className="w-full lg:w-1/2 flex flex-col">
                  <h3 
                    className="font-[family-name:var(--font-inter)] font-normal text-black mb-4 md:mb-6 text-lg md:text-xl"
                  >
                    Managed Services
                  </h3>
                  
                  <ul className="space-y-3 mb-4 md:mb-6">
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/hub.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Managed Connectivity
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/hub.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Managed SD-WAN
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/hub.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Technology Expense Management
                      </span>
                    </li>
                    <li className="flex items-center space-x-3">
                      <Image
                        src="/hub.png"
                        alt="Bullet"
                        width={16}
                        height={16}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-lg md:text-xl lg:text-2xl"
                      >
                        Network Monitoring & Management
                      </span>
                    </li>
                  </ul>
                  
                  <p 
                    className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed text-sm md:text-base"
                  >
                    Managed services offering connectivity, cloud computing, proactive network management and optimization
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>      {/* Contact Section */}
      <AnimatedSection animation="fade-in-left" delay={200}>
        <section className="relative w-full py-12 md:py-20 bg-white">
          <div className="w-full flex items-center justify-center px-4 md:px-6">
            <div className="w-full max-w-[1275px] flex flex-col lg:flex-row lg:items-start lg:space-x-12 space-y-8 lg:space-y-0">
              {/* Column 1 - Contact Information */}
              <div className="w-full lg:w-1/2 flex flex-col justify-between h-full">
                {/* Top Content */}
                <div>
                  <div 
                    className="inline-block w-fit rounded-full px-4 md:px-6 py-2 md:py-3 mb-6 md:mb-8"
                    style={{
                      backgroundColor: "var(--brand-orange-light)",
                      border: "1px solid var(--brand-orange)",
                      color: "var(--brand-orange)"
                    }}
                  >
                    <span 
                      className="font-[family-name:var(--font-poppins)] font-normal text-sm md:text-base"
                    >
                      Talk to an Expert
                    </span>
                  </div>
                  
                  <h2 
                    className="font-[family-name:var(--font-inter)] font-normal text-black leading-tight mb-4 md:mb-6 text-2xl md:text-4xl lg:text-5xl"
                  >
                    Need more information?
                  </h2>
                  
                  <p 
                    className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed mb-8 md:mb-12 text-sm md:text-base"
                  >
                    Tell us about your preferences and we&apos;ll<br className="hidden md:block"/> guide you through the process.
                  </p>
                </div>
                
                {/* Bottom Content - Contact Details */}
                <div className="mt-auto">
                  <h3 
                    className="font-[family-name:var(--font-inter)] font-normal text-black mb-4 md:mb-6 text-xl md:text-2xl"
                  >
                    Contact Us Now
                  </h3>
                  
                  <div className="space-y-3 md:space-y-4">
                    <div className="flex items-center space-x-3">
                      <Image
                        src="/phone.png"
                        alt="Phone"
                        width={20}
                        height={20}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-sm md:text-base"
                      >
                        <a className="underline" href="tel:+94112949203">+94 11 294 9203</a>
                      </span>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      <Image
                        src="/email.png"
                        alt="Email"
                        width={20}
                        height={20}
                        className="flex-shrink-0"
                      />
                      <span 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 text-sm md:text-base"
                      >
                        <a className="underline" href="mailto:info@nadalabs.biz">info@nadalabs.biz</a>
                      </span>
                    </div>
                    
                    <div className="flex items-start space-x-3">
                      <Image
                        src="/location.png"
                        alt="Location"
                        width={20}
                        height={20}
                        className="flex-shrink-0 mt-1"
                      />
                      <div 
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-700 leading-relaxed text-sm md:text-base"
                      >
                    Nada Labs (PVT) LTD<br />
                    Level 35, West Tower<br />
                    World Trade Center,<br />
                    Colombo – 01,<br />
                    Sri Lanka.
                  </div>
                </div>
                  </div>
                </div>
              </div>
              
              {/* Column 2 - Contact Form */}
              <div className="w-full lg:w-1/2">
                <div className="bg-white p-6 md:p-8 rounded-2xl shadow-xl border border-gray-200">
                  <form className="space-y-4 md:space-y-6" onSubmit={handleSubmit} noValidate>
                    {/* Name Fields - Two Columns */}
                    <div className="grid grid-cols-2 gap-3 md:gap-4">
                      <div>
                        <label className="block text-xs md:text-sm font-medium text-gray-700 mb-1 md:mb-2">Name</label>
                        <input
                          type="text"
                          name="firstName"
                          value={formData.firstName}
                          onChange={handleInputChange}
                          required
                          placeholder="John"
                          className="w-full px-3 md:px-4 py-2 md:py-3 rounded-xl md:rounded-2xl border border-gray-400 focus:border-gray-600 focus:outline-none transition-colors text-sm md:text-base"
                        />
                      </div>
                      <div>
                        <label className="block text-xs md:text-sm font-medium text-gray-700 mb-1 md:mb-2">&nbsp;</label>
                        <input
                          type="text"
                          name="lastName"
                          value={formData.lastName}
                          onChange={handleInputChange}
                          placeholder="Doe"
                          className="w-full px-3 md:px-4 py-2 md:py-3 rounded-xl md:rounded-2xl border border-gray-400 focus:border-gray-600 focus:outline-none transition-colors text-sm md:text-base"
                        />
                      </div>
                    </div>

                    {/* Email Field */}
                    <div>
                      <label className="block text-xs md:text-sm font-medium text-gray-700 mb-1 md:mb-2">Email</label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        required
                        autoComplete="email"
                        placeholder="johndoe@example.com"
                        className="w-full px-3 md:px-4 py-2 md:py-3 rounded-xl md:rounded-2xl border border-gray-400 focus:border-gray-600 focus:outline-none transition-colors text-sm md:text-base"
                      />
                    </div>

                    {/* Contact Number Field */}
                    <div>
                      <label className="block text-xs md:text-sm font-medium text-gray-700 mb-1 md:mb-2">Contact No.</label>
                      <input
                        type="tel"
                        name="phone"
                        value={formData.phone}
                        onChange={handleInputChange}
                        autoComplete="tel"
                        inputMode="tel"
                        className="w-full px-3 md:px-4 py-2 md:py-3 rounded-xl md:rounded-2xl border border-gray-400 focus:border-gray-600 focus:outline-none transition-colors text-sm md:text-base"
                      />
                    </div>

                    {/* Message Textarea */}
                    <div>
                      <label className="block text-xs md:text-sm font-medium text-gray-700 mb-1 md:mb-2">Need help? Let us know your preferences.</label>
                      <textarea
                        rows={4}
                        name="message"
                        value={formData.message}
                        onChange={handleInputChange}
                        required
                        className="w-full px-3 md:px-4 py-2 md:py-3 rounded-xl md:rounded-2xl border border-gray-400 focus:border-gray-600 focus:outline-none transition-colors resize-vertical text-sm md:text-base"
                      ></textarea>
                    </div>

                    {/* Checkbox */}
                    <div className="flex items-start space-x-3">
                      <input
                        type="checkbox"
                        id="email-preference"
                        name="marketingOptOut"
                        checked={formData.marketingOptOut}
                        onChange={handleInputChange}
                        className="mt-1 w-4 h-4 text-blue-600 border-gray-400 rounded focus:ring-blue-500"
                      />
                      <label
                        htmlFor="email-preference"
                        className="font-[family-name:var(--font-poppins)] font-normal text-gray-600 leading-relaxed text-xs md:text-sm"
                      >
                        I prefer not to receive emails from Nadalabs about product updates, promotions, marketing tips, or related news. If I don&apos;t check this box, I understand I&apos;ll be automatically subscribed.
                      </label>
                    </div>

                    {/* Submit Button */}
                    <div className="pt-3 md:pt-4">
                      <button
                        type="submit"
                        disabled={isSubmitting}
                        className="cursor-pointer font-[family-name:var(--font-figtree)] w-full rounded-full py-2.5 md:py-3 transition-colors hover:opacity-90 text-sm md:text-base"
                        style={{
                          backgroundColor: "var(--brand-yellow)",
                          color: "#000"
                        }}
                      >
                        {isSubmitting ? 'Sending…' : 'Let\u2019s Talk'}
                      </button>
                    </div>

                    {(feedback || validationErrors.length > 0) && (
                      <div className="space-y-3" aria-live="polite" aria-atomic="true">
                        {feedback && (
                          <div
                            className={`rounded-xl border px-4 py-3 text-sm md:text-base ${
                              feedback.type === 'success'
                                ? 'border-green-200 bg-green-50 text-green-800'
                                : 'border-red-200 bg-red-50 text-red-800'
                            }`}
                          >
                            {feedback.message}
                          </div>
                        )}

                        {validationErrors.length > 0 && (
                          <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm md:text-base text-red-800">
                            <ul className="list-disc space-y-1 pl-5">
                              {validationErrors.map((error) => (
                                <li key={error}>{error}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </form>
                </div>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>      {/* Footer */}
      <AnimatedSection animation="fade-in-up" delay={100}>
        <footer className="bg-black text-white py-12 md:py-20">
          <div className="w-full flex items-center justify-center px-4 md:px-6">
            <div className="w-full max-w-[1275px] flex flex-col lg:flex-row lg:items-start lg:space-x-12 space-y-8 lg:space-y-0">
              {/* Column 1 */}
              <div className="w-full lg:w-1/2 flex flex-col">
                <h2 
                  className="font-[family-name:var(--font-inter)] font-normal text-white leading-tight mb-6 md:mb-8 text-2xl md:text-3xl lg:text-4xl"
                >
                  End-to-End UC Automation for Smarter Business Operations<br className="hidden md:block"/> and Managed Services
                </h2>
                
                <h3 
                  className="font-[family-name:var(--font-poppins)] font-semibold text-white mb-3 md:mb-4 text-lg md:text-xl"
                >
                  Location
                </h3>
                
                <div 
                  className="font-[family-name:var(--font-poppins)] font-normal text-white leading-relaxed text-lg md:text-xl"
                >
                    Nada Labs (PVT) LTD<br />
                    Level 35, West Tower<br />
                    World Trade Center,<br />
                    Colombo – 01,<br />
                    Sri Lanka.
                  </div>
                </div>

                {/* Column 2 */}
              <div className="w-full lg:w-1/2 flex flex-col justify-between h-full">
                {/* Top Content - Email Subscribe */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:space-x-4 space-y-4 sm:space-y-0 mb-8 md:mb-12">
                  <input
                    type="email"
                    placeholder="Enter your email"
                    className="flex-1 px-3 md:px-4 py-2 md:py-3 bg-black border border-gray-600 text-white rounded-lg focus:border-gray-400 focus:outline-none transition-colors text-sm md:text-base"
                  />
                  <button 
                    className="cursor-pointer font-[family-name:var(--font-figtree)] rounded-full px-6 md:px-8 py-2 md:py-3 transition-colors hover:opacity-90 whitespace-nowrap text-sm md:text-base"
                    style={{
                      backgroundColor: "var(--brand-yellow)",
                      color: "#000"
                    }}
                  >
                    Subscribe Us
                  </button>
                </div>
                
                {/* Bottom Content - Follow Us */}
                <div className="mt-auto">
                  <h3 
                    className="font-[family-name:var(--font-poppins)] font-semibold text-white mb-4 md:mb-6 text-lg md:text-xl"
                  >
                    Follow Us
                  </h3>
                  
                  <div className="flex items-center space-x-3 md:space-x-4">
                    {/* Facebook */}
                    <div className="w-10 md:w-12 h-10 md:h-12 bg-black border border-gray-600 rounded-full flex items-center justify-center hover:border-gray-400 transition-colors cursor-pointer">
                      <svg width="16" height="16" className="md:w-5 md:h-5" viewBox="0 0 24 24" fill="white">
                        <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
                      </svg>
                    </div>
                    
                    {/* Google */}
                    <div className="w-10 md:w-12 h-10 md:h-12 bg-black border border-gray-600 rounded-full flex items-center justify-center hover:border-gray-400 transition-colors cursor-pointer">
                      <svg width="16" height="16" className="md:w-5 md:h-5" viewBox="0 0 24 24" fill="white">
                        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                      </svg>
                    </div>
                    
                    {/* Instagram */}
                    <div className="w-10 md:w-12 h-10 md:h-12 bg-black border border-gray-600 rounded-full flex items-center justify-center hover:border-gray-400 transition-colors cursor-pointer">
                      <svg width="16" height="16" className="md:w-5 md:h-5" viewBox="0 0 24 24" fill="white">
                        <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/>
                      </svg>
                    </div>
                    
                    {/* YouTube */}
                    <div className="w-10 md:w-12 h-10 md:h-12 bg-black border border-gray-600 rounded-full flex items-center justify-center hover:border-gray-400 transition-colors cursor-pointer">
                      <svg width="16" height="16" className="md:w-5 md:h-5" viewBox="0 0 24 24" fill="white">
                        <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/>
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </footer>
      </AnimatedSection>
    </div>
  );
}
