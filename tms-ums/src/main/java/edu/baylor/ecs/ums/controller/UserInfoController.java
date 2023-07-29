package edu.baylor.ecs.ums.controller;

import edu.baylor.ecs.ums.entity.Role;
import edu.baylor.ecs.ums.entity.User;
import edu.baylor.ecs.ums.service.UserAccessService;
import org.jboss.resteasy.annotations.ResponseObject;
import org.keycloak.KeycloakPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.security.RolesAllowed;
import java.util.stream.Collectors;

/**
 * This is the REST controller for the UMS backend. It exposes a variety
 * of endpoints which allow access to basic CRUD for keycloak users, as
 * well as other more fine-grained features.
 *
 * @author J.R. Diehl
 * @version 0.1
 */
@RestController
@RequestMapping("/userinfo")
public class UserInfoController {

    @Autowired
    private UserAccessService userAccessService;

    @GetMapping(path = "/users")
    //@PreAuthorize("hasAnyAuthority(ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userAccessService.getUsers());
    }

    @GetMapping(path = "/usernames")
    //@PreAuthorize("hasAnyAuthority('ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin", "ROLE_superadmin"})
    public ResponseEntity<List<String>> getAllUsernames() {
        List<User> users = userAccessService.getUsers();
        List<String> usernames = new ArrayList<>();
        for (User user : users) {
            usernames.add(user.getUsername());
        }

        return ResponseEntity.ok(usernames);

    }

//    @GetMapping(path = "/userRoles/{username}")
//    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
//    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
//    public ResponseEntity<List<String>> getUserRoles(@PathVariable String username) {
//        return ResponseEntity.ok(userAccessService.getUserRoleNames(username));
//    }

    @GetMapping(path = "/validId/{id}")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<Boolean> isValidId(@PathVariable String id) {
        List<User> users = userAccessService.getUsers();
        boolean userExists = false;
        for (User user : users) {
            if (user.getId().equals(id)) {
                userExists = true;
                break;
            }
        }

        if (userExists) {
            return ResponseEntity.ok(true);
        } else {
            return ResponseEntity.ok(false);
        }

    }

    @GetMapping(path = "/emailInUse/{email}")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<String> isEmailInUse(@PathVariable String email) {
        List<User> users = userAccessService.getUsers();
        String userId = null;
        for (User user : users) {
            if (email.equals(user.getEmail())) {
                userId = user.getId();
                break;
            }
        }

        if (userId == null) {
            // Handle the case when no user with the matching email is found
            return ResponseEntity.status(404).body("No user with that email");
        }

        return ResponseEntity.ok(userId);

    }

    @GetMapping(path = "/userById/{id}")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<User> getUserById(@PathVariable String id) {
        List<User> users = userAccessService.getUsers();
        User matchedUser = null;
        for (User user : users) {
            if (id.equals(user.getId())) {
                matchedUser = user;
                break;
            }
        }

        return ResponseEntity.ok(matchedUser);

    }

    @GetMapping(path = "/userByUsername/{username}")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<User> getUserByUsername(@PathVariable String username) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = context.getAuthentication();
        List<User> users = userAccessService.getUsers();

        User matchedUser = null;
        for (User user : users) {
            if (username.equals(user.getUsername())) {
                matchedUser = user;
                break;
            }
        }

        return ResponseEntity.ok(matchedUser);

    }

    @PostMapping(path = "/addUser")
    //@PreAuthorize("hasAnyAuthority('ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<User> addNewUser(@RequestBody User user) {
        return ResponseEntity.ok(userAccessService.addNewUser(user));
    }

    @PostMapping(path = "/addUserRoles/{username}")
    //@PreAuthorize("hasAnyAuthority('ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<List<Role>> addUserRoles(@PathVariable String username, @RequestBody Role[] roles) {
        return ResponseEntity.ok(userAccessService.addUserRoles(username, roles));
    }

    @PutMapping(path = "/updateUser")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<String> updateUser(@RequestBody User user) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = context.getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) auth.getPrincipal();

        boolean isAdmin = false;
        boolean isSuperAdmin = false;
        for (GrantedAuthority authority : auth.getAuthorities()) {
            String authorityName = authority.getAuthority();
            if (authorityName.equals("ROLE_admin")) {
                isAdmin = true;
            } else if (authorityName.equals("ROLE_superadmin")) {
                isSuperAdmin = true;
            }
        }

        if (user.getUsername().equals(principal.getName()) || isAdmin || isSuperAdmin) {
            userAccessService.updateUser(user);
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.status(403).body("Forbidden");
        }

    }

    @PutMapping(path = "/changePassword/{id}")
    //@PreAuthorize("hasAnyAuthority('ROLE_user', 'ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_user","ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<String> changePassword(@PathVariable String id, @RequestBody String newPassword) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = context.getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) auth.getPrincipal();

        List<User> users = userAccessService.getUsers();
        User user = null;
        for (User u : users) {
            if (u.getUsername().equals(principal.getName())) {
                user = u;
                break;
            }
        }

        if (user == null) {
            return ResponseEntity.status(404).body("No such user");
        }

        boolean isAdmin = false;
        boolean isSuperAdmin = false;
        for (GrantedAuthority authority : auth.getAuthorities()) {
            String authorityName = authority.getAuthority();
            if (authorityName.equals("ROLE_admin")) {
                isAdmin = true;
            } else if (authorityName.equals("ROLE_superadmin")) {
                isSuperAdmin = true;
            }
        }

        if (user.getId().equals(id) || isAdmin || isSuperAdmin) {
            userAccessService.changeUserPassword(id, newPassword);
            return ResponseEntity.ok("Password changed successfully!");
        } else {
            return ResponseEntity.status(403).body("Forbidden");
        }

    }

    @DeleteMapping(path = "/deleteUser/{id}")
    //@PreAuthorize("hasAnyAuthority('ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<String> removeUser(@PathVariable String id) {
        List<User> users = userAccessService.getUsers();
        boolean userFound = false;
        for (User user : users) {
            if (id.equals(user.getId())) {
                userFound = true;
                break;
            }
        }

        if (!userFound) {
            return ResponseEntity.status(404).body("No user with that id");
        }

        userAccessService.removeUser(id);
        return ResponseEntity.noContent().build();

    }

    @DeleteMapping(path = "/deleteUserByUsername/{username}")
    //@PreAuthorize("hasAnyAuthority('ROLE_admin', 'ROLE_superadmin')")
    @RolesAllowed({"ROLE_admin","ROLE_superadmin"})
    public ResponseEntity<String> removeUserByUsername(@PathVariable String username) {
        List<User> users = userAccessService.getUsers();
        String id = null;
        for (User user : users) {
            if (username.equals(user.getUsername())) {
                id = user.getId();
                break;
            }
        }

        if (id == null) {
            return ResponseEntity.notFound().build();
        }

        userAccessService.removeUser(id);
        return ResponseEntity.noContent().build();

    }

}
