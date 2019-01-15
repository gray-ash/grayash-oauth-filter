package com.github.grayash.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;

import com.github.grayash.security.EnableGrayashSecurity;



@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class SecurityImportSelector implements ImportSelector {

	private static final Logger Log = LoggerFactory.getLogger(SecurityImportSelector.class);

	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		AnnotationAttributes attributes = AnnotationAttributes
				.fromMap(importingClassMetadata.getAnnotationAttributes(EnableGrayashSecurity.class.getName(), false));
		boolean enable = attributes.getBoolean("enable");
		if(enable)
			return new String[] { "com.github.grayash.security.config.WebSecurityConfig" };
		else
			return new String[] { "com.github.grayash.security.config.AllowWebSecurityConfig" };
	}

	

}
