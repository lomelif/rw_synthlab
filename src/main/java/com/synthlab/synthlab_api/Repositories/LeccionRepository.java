package com.synthlab.synthlab_api.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.synthlab.synthlab_api.Entities.Leccion;

public interface LeccionRepository extends JpaRepository<Leccion, Long> {
}
