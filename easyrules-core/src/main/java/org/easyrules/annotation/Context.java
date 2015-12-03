package org.easyrules.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to inject context objects in rules.
 * Must annotate any field of a {@link org.easyrules.api.Rule} Object.
 *
 * @author Mahmoud Ben Hassine (mahmoud@benhassine.fr)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Context {

    String key() default "";
}
