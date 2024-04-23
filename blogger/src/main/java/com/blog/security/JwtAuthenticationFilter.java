package com.blog.security;

import com.blog.exception.BlogAPIException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    // So what is doFilter method doing here?
    // For every incoming request it extracts the Jwt Token and if it is a valid Token 
    // It processes the request and sends the response back

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // doFilter method  which we are overriding it  which is coming from  OncePerRequestFilter

            // Retrieve JWT token from the Authorization header
            // request  in the POSTMAN  http://localhost:8080/api/posts
            String token = getJwtFromRequest(request);

            // validate token

        try {
            // tokenProvider.validateToken(token) --> we ar calling validateToken method in
            // JwtTokenProvider.java and this (tokenProvider) is the object of JwtTokenProvider class
            // Now when we validate the Token means this condition happens to be true:
            if (StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
                // then tokenProvider gets username from the Token:
                // Extract (get) user id from JWT Token
                String username = tokenProvider.getUsernameFromJWT(token);
                // And then it will call the method  loadByUsername:
                // load user associated with token
                // here we have called loadBy username method
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                // What loadByUsername do  it takes the username  goes to the database  and based
                // on the username  it gets the details  so that detail is present in this  now:
                //Inside  userDetails

                // Create authentication token
                // username passwordAuthenticationToken we have created in AuthController also inside Signin feature
                // And now same way we are initializing the required things:
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // And setting up the authentication Token  telling that it’s a valid Token:
                // Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

//                // Calculate remaining time until token expiration (in milliseconds)
//                long remainingTimeMillis = tokenProvider.getRemainingTimeInMillis(token);
//
//                // rest part in JwtTokenProvider
//                // Convert to human-readable format
//                long remainingSeconds = remainingTimeMillis / 1000;
//                long remainingMinutes = remainingSeconds / 60;
//                long remainingHours = remainingMinutes / 60;
//
//                // Print or log the remaining time
//                System.out.println("Time remaining until token expiration:");
//                System.out.println("Hours: " + remainingHours);
//                System.out.println("Minutes: " + remainingMinutes % 60);
//                System.out.println("Seconds: " + remainingSeconds % 60);

            }
        } catch (BlogAPIException e) {
            throw new RuntimeException(e);
        }


        filterChain.doFilter(request, response);
    }

    // Bearer<accessToken>
    // this method (getJwtFromRequest) based on the request  it extracts the Token out of it

    private String getJwtFromRequest(HttpServletRequest request) {
        // this method based on the request  it extracts the Token out of it
        //so from the request I am getting the Token:
        //getJwtFromRequest(request);
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}



//First step  It is generating Token  flow is:
//Flow: 1
//It calls AuthController  It calls  generateToken method  This method takes  secretKey and Expiry time  It applies an Algorithm  generates a Token and gives it
//Flow: 2
//When I enters the Token  JwtAuthenticationFilter.java class  comes in picture  the name itself says  I will filter the Token based on  whether it is valid or not
//It has doFilter method (doFilterInternal)  based on the incoming Http request (request) 
//What it does  It will give Http request to  getJwtFrom the request:
//String token = getJwtFromRequest(request);
//
//Which request  in the POSTMAN  http://localhost:8080/api/posts
//And with this request I am sending  JWT Token:
//eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJyYWRoZUBnbWFpbC5jb20iLCJpYXQiOjE3MTIwNjI0NjEsImV4cCI6MTcxMjY2NzI2MX0._9_6HO6fRF5rK4Q_q0npsHkfOcn7xy21yQP_qUroFdPIfMlA_Xzd_jNaIYhVec945VeR98twarjWW5WsROPYyQ
//
//And that request automatically comes to  doFilter method  which we are overriding it  which is coming from  OncePerRequestFilter
//Interview Question:
//What is doFilter method used for ?
//Second time when you want to access some content from the back end  In the request there is a JWT Token doFilter method has a request object  which automatically takes the incoming request and that request has JWT Token
//There is method which is developed  getJwtFromRequest 
//private String getJwtFromRequest(HttpServletRequest request) {
//
//    this method based on the request  it extracts the Token out of it
//    so from the request I am getting the Token:
//    getJwtFromRequest(request);
//
//    because before I process the request  I need to validate the Token and  only in valid I will process the request and send the response back

