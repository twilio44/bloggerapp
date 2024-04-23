package com.blog.controller;


import com.blog.entity.Role;
import com.blog.entity.User;
import com.blog.payload.JWTAuthResponse;
import com.blog.payload.LoginDto;
import com.blog.payload.SignUpDto;
import com.blog.repository.RoleRepository;
import com.blog.repository.UserRepository;
import com.blog.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

// Auth means --> Authentication Controller
// restApi signin implementation with MySQL and use Authentication manager --> search in Chat Gpt to get this code

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;   // user Repository

    @Autowired
    private PasswordEncoder passwordEncoder;  // Whenever you save the password in your database  the password should be  encoded, So apply @Autowired and use

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private JwtTokenProvider tokenProvider;


    // http://localhost:8080/api/auth/signin
    // at last we have Signin detail

    @PostMapping("/signin")
    public ResponseEntity<JWTAuthResponse> authenticateUser(@RequestBody LoginDto loginDto){ // here we are getting the details from JASON and in CustomUserDetailsService.java we are getting the details from database
        // <JWTAuthResponse> --> this is your payload
        // here we can use if condition --> see in the last all coding --> but we will not do it here --> spring security takes care all these things --> in a very proper way --> with its built in implementation

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getUsernameOrEmail(), loginDto.getPassword());

        // above now this(usernamePasswordAuthenticationToken) object has username, email and password
        // when you take this object and give to --> authenticationManager.authenticate --> see below
        // Automatically the username from here will go to loadByUsername (In CustomUserDetailsService.java)
        // and loadByUsername will get the data from database and that data we are getting from database
        // it will compare to the value present in it (usernamePasswordAuthenticationToken) --> see below
        // when this comparison becomes successful --> it will help us to generate one authentication reference (authentication)
        // and this authentication reference we will store it in --> SecurityContextHolder --> which is like a session variable
        // usernamePasswordAuthenticationToken --> this object consist of user defined username and password

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        // Who is helping us to compare these two things(matching between user entered username, password and username,
        // password in database) --> authenticate method
        // expected value is in --> usernamePasswordAuthenticationToken and actual value --> authenticate method automatically call
        // loadByUsername and gets the actual value from it and then compare expected and actual value after comparison it will set
        // the details into the context --> and if context is set to the right detail --> then elegible to use application

        // instead of using above coding we will use below codes becuase there is a less number of lines

        // Above we have split the below codes for understanding purpose

//        Authentication authentication = authenticationManager.authenticate(  // this is like --> if condition
//                new UsernamePasswordAuthenticationToken(
//                loginDto.getUsernameOrEmail(), loginDto.getPassword()));

        // authenticationManager --> to compare the data coming from database and data in loginDto
        // ContextHolder --> this is like a session variable --> whenever login is successful --> we are creating session variable -->
        // and once the value is in session variable -> which means user has logged in --> and if the value in session variable is invalid --> it means the use has not logged in
        // so we are eligible to use the application --> if the value in the session variable is --> success
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // this line is like --> session.setAttribute
        // get token from tokenProvider
        String token = tokenProvider.generateToken(authentication);
        // so there is already a method --> generateToken  above present inside the class --> tokenProvider
        // this method takes --> secret key and expiry time
        return ResponseEntity.ok(new JWTAuthResponse(token));
        // JWTAuthResponse --> this is a payload, it will initialize the accessToken in JwtAuthResponse

        //            Flow of JWT TOKEN

//        When you login   It will call the signin  Signin will then call
//        tokenProvider will call  generateToken method  generateToken method will take the secret
//        key and expiry time from properties file, and it will generate a token, once a token is
//        generated, it will return back to AuthController and AuthController will return back that as a
//        JWT response  JWT Response again a class that I developed it  which has accessToken and
//        tokenType is – Bearer (which is hard coded) so these two information will be your payload
//        payload will have now  accessToken   that is the token which has three parts  Header,
//        Body and Signature  and the type of the token will be  Bearer
//        once you get the token then second part of the execution will begins

    }


//    Now that username and password which is now present in the LoginDto  You will have to
//    compare that with the database
//    How to compare username and password with database?
//    here we will not use if Condition
//    If(loginDto.getEmail equals user.getEmail and loginDto.getPassword equals user.Password)
//    This comparison to be done  we will leave this to your Spring Security framework
//    we will build Custom User Detail Service class

    // http://localhost:8080/api/auth/signup
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpDto signUpDto) {
        // above signUpDto will get the JSON detail, we have created SignUpDto class

        if (userRepository.existsByEmail(signUpDto.getEmail())){
            return new ResponseEntity<>("Email id exists :"+signUpDto.getEmail(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        // Above this --> userRepository.existsByEmail(signUpDto.getEmail())) --> is calling the method in UserRepository
        // if(userRepository.existsByEmail(signUpDto.getEmail())!=null) --> no need to write --> getEmail() ! = null --> because it is already returning --> true and false --> and if condition work based on  true and false

        if(userRepository.existsByUsername(signUpDto.getUsername())) {
            return new ResponseEntity<>("username exist: " +signUpDto.getUsername(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        // if username of JSON and Database will match then if condition will become true

        User user = new User();
        user.setName(signUpDto.getName());
        user.setEmail(signUpDto.getEmail());
        user.setUsername(signUpDto.getUsername());
        user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));
        // we can see in the database table (user) that password has encoded
        // when we sign up --> you are not only setting up the name, Email, Username and
        // Password (just above) but you are --> Also defining the --> role for it (see below)
        // so this user who sign up is an --> admin user --> once he is an admin user --> he can create a post and delete a post
        // but if you login as a --> non Admin user --> then you are able to only see the post --> that is get all post

        Role roles = roleRepository.findByName("ROLE_ACCOUNTANT").get();// it will give me role object (and it has set of roles)
        // convert Role object to --> set --> by using --> Collections.singleton(roles)
        // because set role is taking --> set --> in User.java --> private Set<Role> roles;
        // ROLE_ACCOUNTANT has the id number --> 3, so in user_roles Table role_id will become 3
        // and whatever will be the id of user at the time of storing user details that will become user_id

        // see detail of above line at last

        //    below is for giving multiple roles to single user

//        Role roles2 = roleRepository.findByName("ROLE_ADMIN").get();
//
//        Set<Role> userRoles = new HashSet<>(); // Create a set to hold roles
//        userRoles.add(roles1);
//        userRoles.add(roles2);
//        user.setRoles(userRoles);

        user.setRoles(Collections.singleton(roles));
        // after converting into set it will store into the object --> user
        // user.setRoles(roles); --> it will be wrong becuase input to this(setRoles) --> should be a set

        User savedUser = userRepository.save(user);

        // TABLE DETAIL AT LAST

        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);

        // .antMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
        // above is the permission given in the SecurityConfig.java
    }
//    detail in page no. --> 76 --> Java-Pankaj_sir-6

}

// we could simply compare the username password by using if condition --> inside --> @PostMapping("/signin")

//        User user = userRepository.findByUsernameOrEmail(loginDto.getUsernameOrEmail(), loginDto.getUsernameOrEmail()).get();

// I am using same parameter in both place --> loginDto.getUsernameOrEmail() -->
// because i would have entered username or email in the same place --> either i will enter username or email
//
//        if (loginDto.getUsernameOrEmail().equals(user.getEmail())&&loginDto.getPassword().equals(user.getPassword()) {
//
//        }else{
//
//        }


//We have two table roles1 and user_role (this is third table)
// user table ---->   id    email          name    password    username
//                    1     a@gmail.com     a       xyz           a

// users_roles table --->  user_id    role_id
//                            1          2

// meaning of above table --> user whose id is 1 --> he has a role who has id 2 --> in role table

// Detail of:               Role roles = roleRepository.findByName("ROLE_ADMIN").get();
//                           user.setRoles(Collections.singleton(roles));

//This code fetches the role with the name "ROLE_ADMIN" from the database and assigns it to the user being registered.
//
//        Therefore, when you make a request to signup with the JSON content:
//
//json
//Copy code
//{
//        "name": "shyam",
//        "username": "shyam",
//        "email": "shyam@gmail.com",
//        "password": "testing"
//        }
//The role assigned to the user "shyam" would be "ROLE_ADMIN".


//                                    Signin feature without JWT

//                   ONLY CHANGING THE RETURN TYPE IN ABOVE SIGNIN

//@PostMapping("/signin")
//public ResponseEntity<String> authenticateUser(@RequestBody LoginDto loginDto){ // here we are getting the details from JASON and in CustomUserDetailsService.java we are getting the details from database
//
//    // here we can use if condition --> see in the last all coding --> but we will not do it here --> spring security takes care all these things --> in a very proper way --> with its built in implementation
//
//    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//            loginDto.getUsernameOrEmail(), loginDto.getPassword());
//
//    // above now this(usernamePasswordAuthenticationToken) object has username, email and password
//    // when you take this object and give to --> authenticationManager.authenticate --> see below
//    // Automatically the username from here will go to loadByUsername (In CustomUserDetailsService.java)
//    // and loadByUsername will get the data from database and that data we are getting from database
//    // it will compare to the value present in it (usernamePasswordAuthenticationToken) --> see below
//    // when this comparison becomes successful --> it will help us to generate one authentication reference (authentication)
//    // and this authentication reference we will store it in --> SecurityContextHolder --> which is like a session variable
//    // usernamePasswordAuthenticationToken --> this object consist of user defined username and password
//
//    Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
//
//    // Who is helping us to compare these two things(matching between user entered username, password and username,
//    // password in database) --> authenticate method
//    // expected value is in --> usernamePasswordAuthenticationToken and actual value --> authenticate method automatically call
//    // loadByUsername and gets the actual value from it and then compare expected and actual value after comparison it will set
//    // the details into the context --> and if context is set to the right detail --> then elegible to use application
//
//    // instead of using above coding we will use below codes becuase there is a less number of lines
//
//    // Above we have split the below codes for understanding purpose
//
////        Authentication authentication = authenticationManager.authenticate(  // this is like --> if condition
////                new UsernamePasswordAuthenticationToken(
////                loginDto.getUsernameOrEmail(), loginDto.getPassword()));
//
//    // authenticationManager --> to compare the data coming from database and data in loginDto
//    // ContextHolder --> this is like a session variable --> whenever login is successful --> we are creating session variable -->
//    // and once the value is in session variable -> which means user has logged in --> and if the value in session variable is invalid --> it means the use has not logged in
//    // so we are eligible to use the application --> if the value in the session variable is --> success
//    SecurityContextHolder.getContext().setAuthentication(authentication);
//    // this line is like --> session.setAttribute
//    return new ResponseEntity<>("User signed-in successfully!.", HttpStatus.OK);
//}