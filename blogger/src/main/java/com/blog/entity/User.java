package com.blog.entity;

//import javax.management.relation.Role;
import lombok.Data;

import javax.persistence.*;
//import java.util.HashSet;
import java.util.Set;

@Data
@Entity
//@Table(name = "users", uniqueConstraints = {
//        @UniqueConstraint(columnNames = {"username"}),
//        @UniqueConstraint(columnNames = {"email"})
//})
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String name;
    private String password;
    private String username;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    private Set<Role> roles;

    // Constructors, getters, and setters

}

