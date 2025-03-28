package com.synthlab.synthlab_api.Services;

import java.util.List;
import org.springframework.stereotype.Service;

import com.synthlab.synthlab_api.Entities.Avatar;
import com.synthlab.synthlab_api.Repositories.AvatarRepository;

@Service
public class AvatarService {
    private final AvatarRepository avatarRepository;

    public AvatarService(AvatarRepository avatarRepository) {
        this.avatarRepository = avatarRepository;
    }

    public List<Avatar> getAllAvatars() {
        return avatarRepository.findAll();
    }

    public Avatar getAvatarById(Long id) {
        return avatarRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado con ID: " + id));
    }

    public Avatar createAvatar(Avatar avatar) {
        return avatarRepository.save(avatar);
    }

    public Avatar updateAvatar(Long id, Avatar avatarDetails) {
        Avatar avatar = getAvatarById(id);
        avatar.setImg(avatarDetails.getImg());

        return avatarRepository.save(avatar);
    }

    public void deleteAvatar(Long id) {
        Avatar avatar = getAvatarById(id);
        avatarRepository.delete(avatar);
    }
}
