/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import java.util.List;
import java.util.Map;
import javax.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;


/**
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that performs the web
 * based security for Spring Security. It then exports the necessary beans. Customizations
 * can be made to {@link WebSecurity} by extending {@link WebSecurityConfigurerAdapter}
 * and exposing it as a {@link Configuration} or implementing
 * {@link WebSecurityConfigurer} and exposing it as a {@link Configuration}. This
 * configuration is imported when using {@link EnableWebSecurity}.
 *
 * @see EnableWebSecurity
 * @see WebSecurity
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @since 3.2
 */
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	private ClassLoader beanClassLoader;

	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return webSecurity.getExpressionHandler();
	}

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();

		// 没有通过继承WebSecurityConfigurerAdatper类配置过Spring Security，
		// 则会以WebSecurityConfigurerAdatper中的配置默认行为。
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}

		// 调用WebSecurity类的build方法构建过滤器链。
		return webSecurity.build();
	}

	/**
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary for the JSP
	 * tag support.
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param webSecurityConfigurers the
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
    // objectPostProcess用于初始化对象，暂时不用关注。webSecurityConfigurers是通过SpEL调用Bean的方法获得的值，其获得的是我们在配置Spring Security时继承自WebSecurityConfigurerAdapter的配置类
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(
			ObjectPostProcessor<Object> objectPostProcessor,
			@Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
			throws Exception {
        // 初始化WebSecurity
		webSecurity = objectPostProcessor
				.postProcess(new WebSecurity(objectPostProcessor));
		if (debugEnabled != null) {
			webSecurity.debug(debugEnabled);
		}
        
		// 对webSecurityConfigurers按升序进行排序（排序算法是稳定的），如果一个应用中有多个SecurityConfigurer，可通过@Order注解指定其顺序，注解中的值越大，SecurityConfigurer排序后越靠后。
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);

		Integer previousOrder = null;
		Object previousConfig = null;
		// 检查多个SecurityConfigurer配置的@Order注解值是否相同，如果相同则报错。这就说明如果代码中通过继承自WebSecurityConfigurerAdapter配置了多个SecurityConfigurer，则必须为每个SecurityConfigurer设置@Order注解，并且注解值不能相同。
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException(
						"@Order on WebSecurityConfigurers must be unique. Order of "
								+ order + " was already used on " + previousConfig + ", so it cannot be used on "
								+ config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}

	// 将配置的每一个SecurityConfigurer应用到WebSecurity。这里我们顺便看下WebSecurity类的apply函数(WebSecurity继承自AbstractConfiguredSecurityBuilder，apply函数位于AbstractConfiguredSecurityBuilder中。)，因为后面的代码分析会用到。
	for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	@Bean
	public static AutowiredWebSecurityConfigurersIgnoreParents autowiredWebSecurityConfigurersIgnoreParents(
			ConfigurableListableBeanFactory beanFactory) {
		return new AutowiredWebSecurityConfigurersIgnoreParents(beanFactory);
	}

	/**
	 * A custom verision of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {
		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = (obj instanceof Class ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.context.annotation.ImportAware#setImportMetadata(org.
	 * springframework.core.type.AnnotationMetadata)
	 */
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
				.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes
				.fromMap(enableWebSecurityAttrMap);
		debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (webSecurity != null) {
			webSecurity.debug(debugEnabled);
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.beans.factory.BeanClassLoaderAware#setBeanClassLoader(java.
	 * lang.ClassLoader)
	 */
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}
}
