import React from "react";
import Link from "next/link";
import { ArrowUpRight } from "lucide-react";

type Variant = "primary" | "secondary" | "outline" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

const variantClass: Record<Variant, string> = {
  primary: "editorial-btn-primary border-2 border-ink",
  secondary: "editorial-btn-outline border-2 border-ink",
  outline: "editorial-btn-outline border-2 border-ink",
  ghost: "border border-transparent hover:underline underline-offset-4",
  danger: "border border-critical text-critical hover:bg-critical hover:text-white",
};

const sizeClass: Record<Size, string> = {
  sm: "px-3 py-1.5 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-5 py-3 text-sm",
};

const base = "editorial-btn inline-flex items-center justify-center gap-2 font-bold tracking-[-.01em] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent disabled:pointer-events-none disabled:opacity-50 cursor-pointer";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export function Button({ variant = "secondary", size = "md", className = "", type = "button", children, ...props }: ButtonProps) {
  return <button type={type} className={`${base} ${variantClass[variant]} ${sizeClass[size]} ${className}`} {...props}>{children}</button>;
}

export interface ButtonLinkProps extends React.ComponentProps<typeof Link> {
  variant?: Variant;
  size?: Size;
}

export function ButtonLink({ variant = "secondary", size = "md", className = "", children, ...props }: ButtonLinkProps) {
  return (
    <Link className={`${base} ${variantClass[variant]} ${sizeClass[size]} ${className}`} {...props}>
      {children}
      <ArrowUpRight aria-hidden="true" className="h-4 w-4" />
    </Link>
  );
}
