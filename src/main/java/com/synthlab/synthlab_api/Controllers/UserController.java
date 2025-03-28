package com.synthlab.synthlab_api.Controllers;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.synthlab.synthlab_api.Entities.User;
import com.synthlab.synthlab_api.Services.UserService;

@RestController
@RequestMapping("users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // @GetMapping
    // public List<User> getAllUsers() {
    //     return userService.getAllUsers();
    // }

    // @GetMapping("/{id}")
    // public User getUserById(@PathVariable Long id) {
    //     return userService.getUserById(id);
    // }

    // @PostMapping
    // public User createUser(@RequestBody User user) {
    //     return userService.createUser(user);
    // }

    @PutMapping("/{id}")
    public User updateUser(@PathVariable Long id, @RequestBody User userDetails) {
        return userService.updateUser(id, userDetails);
    }

    // @DeleteMapping("/{id}")
    // public String deleteUser(@PathVariable Long id) {
    //     userService.deleteUser(id);
    //     return "Se ha eliminado el usuario con el ID: " + id;
    // }
}
