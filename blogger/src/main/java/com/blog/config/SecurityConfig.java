package com.blog.config;

import com.blog.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//In order to use PreAuthorize Annotationin in your controller layer you have to add this(prePostEnabled) here:
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//which was telling that  Enable this Annotation  Globally in all  Controller layers
//@EnableGlobalMethodSecurity(prePostEnabled = true)


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
// @EnableWebSecurity  help us for web authentication
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // we have used configure method for --> which URL can be accessed by whom and that we are doing in security config class that extends --> WebSecurityConfigurerAdapter

    @Autowired
    private CustomUserDetailsService userDetailsService;
    // here we have created a bean of userDetailsService

//    @Autowired
//    private PasswordEncoder passwordEncoder;
    // here we have created a bean again

    @Autowired
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
        // it will create an object of --> AuthenticationManager --> and inject address into -->
        // AuthenticationManager authenticationManager --> in AuthController.java
        // by writing above code Spring will create the AuthenticationManager bean, and your
        // AuthController will be able to find it during dependency injection.
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        // above one http object is created and below http object is calling .csrf().disable()

        http
                .csrf().disable()
                .authorizeRequests()
                //.antMatchers(HttpMethod.GET, "/api/**").authenticated()
                // if we will give above line and remove below two line then we require to give username and password in the browser after giving URL --> http://localhost:8080/api/posts
                // If we will remove --> permitAll() --> then we require username and password otherwise no need to give username and password to get the data in the browser
                .antMatchers(HttpMethod.GET, "/api/**").permitAll()
                //.antMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
                // giving permisstion to the URL in the POSTMAN --> http://localhost:8080/api/auth/signup
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    // details of below override method is in page-26 - pankajsir -6
    // How to override below method --> right click in this program --> generate --> select  userDetailsService():UserDetailsService  Ok
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//
//        // below we have created two objects and object consist of User Role and Admin Role
//
////        UserDetails user = User.builder().username("pankaj").password("test").roles("USER").build();
////        UserDetails admin = User.builder().username("admin").password("admin").roles("ADMIN").build();
//        // above password is not encoded, see below encoded password
//          UserDetails user = User.builder().username("pankaj").password(passwordEncoder.encode("testing")).roles("USER").build();
//          UserDetails admin = User.builder().username("admin").password(passwordEncoder.encode("Admin")).roles("ADMIN").build();
//
//        // we have given @PreAuthorize annotation("hasRole('ADMIN')") on DeleteMapping, PutMapping and PostMapping so it only ADMIN can access that feature
//        // ctrl+click on builder and we can see there are inbuilt methods username() and password() in the builder method
//        // builder method build an object and throgh that object we are calling username and password method and initializing the variable
//        // in POSTMAN if we give JSON content and then send --> it will give Unauthorize because we need to give username and password
//        // so click on Authorization --> inherit Auth --> Basic Auth --> give username and password --> send --> and we can see the JSON content has saved
//
//        // return super.userDetailsService();
//
//        return new InMemoryUserDetailsManager(user,admin);
//
//        // Now this is InMemory Authentication  now username password will be taken from this object,  It should come from database  database implementation we have not done it yet
//
//        // apply @PreAuthorize("hasRole('ADMIN')") in Controller layer before PostMapping and DeleteMapping, which means only Admin can delete and create the post
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(getEncodedPassword());

        // we have to create the bean of --> userDetailsService --> see on top
        // previosly we were getting the error --> error creating the bean
    }

    @Bean
    public PasswordEncoder getEncodedPassword() {
        return new BCryptPasswordEncoder();
        // it is already creating a bean here and going above --> (getEncodedPassword())
        // and top of the program we have again created a bean so comment that

        // previously these code were in Blogger1Application.java
    }
}
// Blogger1Application is also a configuration

//This method:      Configure(HttpSecurity http)
//is coming from this class:      WebSecurityConfigurerAdapter
//What this method does  you are inheriting this method from  WebSecurityConfigurerAdapter
//Because this method is the one that can control the access of the URLs



// we have changed the version from  3.2.0 to  2.7.17

// previously our import was --> jakarta -->  import jakarta.validation.Valid;   But Now
// our import is --> import javax.validation.Valid;  so change everywhere in the application

//Here I am just trying to reduce the version and trying to match the compatibility  because this is where open source becomes little dangerous
//        When the compatibility issues happens to persist there and the problem will be on the developers side

//What does it mean:
//        .authorizeRequests()  -->  (I am authorizing)
//.anyRequest().authenticated() -->  (Anu request  to be authenticated)
//Above lines meaning is  I am authorizing  Anu request  to be authenticated

//antMatchers:

//This antMatchers is a method where you define  which URL  who can access
//Like getMapping who can access, postMapping who can access, which URL without password who can access  that configuration happens here
//Interview question:
//What is the purpose of configure method in Spring Security
//This is where we configure  which URL  who is going to access
//        .antMatchers(HttpMethod.GET, "/api/**").permitAll()
//
//All that URL that happens to begins with /api/**  
// All that Http method that happens to be starting with  /api/**  just do  permitAll()
// Which means  getMapping doesn’t require username password to access
// Username and password is now required only for POST, PUT and DELETE
// Let us say I want PostMapping only for admin to access so again write 
// .antMatchers(HttpMethod.POST, "/api/**").hasRole("ROLE_ADMIN")
// .hasRole("ROLE_ADMIN")   which means all the PostMapping URL  only an Admin can access
//
// So we will keep on adding  antMatchers  like this

// .hasRole("ADMIN")

//Here's what .hasRole("ADMIN") does:

//It specifies that the HTTP POST requests to URLs starting with "/api/" should
// only be allowed for users who have the role "ADMIN".
//This means that only users authenticated with the role "ADMIN" will be permitted
// to access these POST endpoints. If a user doesn't have the role "ADMIN", they
// will receive a 403 Forbidden error when trying to access these endpoints.


//Version changed

//        Now version has been changed:

//        <parent>
//              <groupId>org.springframework.boot</groupId>
//              <artifactId>spring-boot-starter-parent</artifactId>
//              <version>2.7.17</version>
//              <relativePath/> <!-- lookup parent from repository -->
//        </parent>

//
//        Version is  2.7.17

