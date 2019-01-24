package com.grayash.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import com.grayash.security.util.SecurityImportSelector;


@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SecurityImportSelector.class)
public @interface EnableGrayashSecurity {
	boolean enable() default true;

}
