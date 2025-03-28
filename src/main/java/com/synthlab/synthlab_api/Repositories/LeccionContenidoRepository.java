package com.synthlab.synthlab_api.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.synthlab.synthlab_api.Entities.LeccionContenido;

public interface LeccionContenidoRepository extends JpaRepository<LeccionContenido, Long> {
}
