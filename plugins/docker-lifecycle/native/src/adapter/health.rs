//! One-shot detached health execution; only subsequent inspection may repeat.
use super::*;
impl<F: Fn() -> bool> Engine<'_, F> {
    pub(super) fn health(&self, target: &Target, argv: &[String]) -> Result<Outcome> {
        let before = self.inspect(target, None)?;
        if before.state != ContainerState::Running {
            return Err("health requires running container");
        }
        let body=serde_json::to_vec(&serde_json::json!({"Cmd":argv,"AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"Privileged":false})).map_err(|_|"health encoding failed")?;
        let reply = self.exchange("POST", &self.path(&target.object_id, "exec"), &body)?;
        if reply.status != 201 {
            return Err("health create uncertain");
        }
        let exec_id = crate::docker::exec_created(&reply.body)?;
        let path = format!("/v{}/exec/{exec_id}", self.config.api_version);
        let reply = self.exchange(
            "POST",
            &format!("{path}/start"),
            br#"{"Detach":true,"Tty":false}"#,
        )?;
        if reply.status != 200 || !reply.body.is_empty() {
            return Err("health start uncertain");
        }
        let exit_code = loop {
            let reply = self.exchange("GET", &format!("{path}/json"), &[])?;
            if reply.status != 200 {
                return Err("health inspect uncertain");
            }
            if let Some(code) = crate::docker::exec_exit(&reply.body, &exec_id, &target.object_id)?
            {
                break code;
            }
            let next = (Instant::now() + Duration::from_millis(100)).min(self.deadline);
            while Instant::now() < next {
                if (self.cancelled)() {
                    return Err("health cancelled");
                }
                std::thread::sleep(
                    next.saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(10)),
                );
            }
            if Instant::now() >= self.deadline || (self.cancelled)() {
                return Err("health deadline or cancellation");
            }
        };
        let object = self.inspect(target, None)?;
        if object.state != ContainerState::Running {
            return Err("health container changed");
        }
        Ok(Outcome::Health {
            exec_id,
            exit_code,
            object,
        })
    }
}
