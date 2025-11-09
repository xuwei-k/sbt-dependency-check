/*
 * Copyright 2025 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.dependencycheck

import sbt.Def.Classpath
import sbt.ModuleID
import sbt.internal.util.Attributed
import sbt.Configuration
import sbt.UpdateReport
import scala.annotation.unused
import java.io.File
import xsbti.FileConverter

private[dependencycheck] object DependencyCheckCompat {
  def getModuleId[A](x: Attributed[A]): Option[ModuleID] =
    x.get(sbt.Keys.moduleID.key)

  def managedJars(
      config: Configuration,
      jarTypes: Set[String],
      up: UpdateReport,
      @unused converter: FileConverter
  ): Classpath =
    sbt.Classpaths.managedJars(config, jarTypes, up)

  def classpathToFiles(
      classpath: Classpath,
      @unused converter: FileConverter
  ): Seq[Attributed[File]] = classpath

}
