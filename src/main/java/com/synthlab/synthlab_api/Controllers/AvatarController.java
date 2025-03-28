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

import com.synthlab.synthlab_api.Entities.Avatar;
import com.synthlab.synthlab_api.Services.AvatarService;

@RestController
@RequestMapping("avatars")
public class AvatarController {
    private final AvatarService avatarService;

    public AvatarController(AvatarService avatarService) {
        this.avatarService = avatarService;
    }

    @GetMapping
    public List<Avatar> getAllAvatars() {
        return avatarService.getAllAvatars();
    }

    @GetMapping("/{id}")
    public Avatar getAvatarById(@PathVariable Long id) {
        return avatarService.getAvatarById(id);
    }

    @PostMapping
    public Avatar createAvatar(@RequestBody Avatar avatar) {
        return avatarService.createAvatar(avatar);
    }

    @PutMapping("/{id}")
    public Avatar updateAvatar(@PathVariable Long id, @RequestBody Avatar avatarDetails) {
        return avatarService.updateAvatar(id, avatarDetails);
    }

    @DeleteMapping("/{id}")
    public String deleteAvatar(@PathVariable Long id) {
        avatarService.deleteAvatar(id);
        return "Se ha eliminado el usuario con el ID: " + id;
    }
}
