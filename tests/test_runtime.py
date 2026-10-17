import pytest

from agent_sandbox.runtime import RuntimeCheckError, check, oci_seccomp_enabled


def info(runsc=None, default="runc"):
    runtimes = {"io.containerd.runc.v2": {"path": "runc"}, "runc": {"path": "runc"}}
    if runsc is not None:
        runtimes["runsc"] = runsc
    return {"Runtimes": runtimes, "DefaultRuntime": default, "KernelVersion": "6.8.0"}


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ([], False),
        (["--oci-seccomp"], True),
        (["-oci-seccomp"], True),
        (["--oci-seccomp=true"], True),
        (["--oci-seccomp=1"], True),
        (["--oci-seccomp=false"], False),
        (["--oci-seccomp=yes"], False),  # runsc refuses to parse it
        (["--oci-seccomp", "--oci-seccomp=false"], False),
        (["--oci-seccomp=false", "--platform=ptrace", "--oci-seccomp"], True),
        (["--oci-seccomp-extra"], False),
    ],
)
def test_oci_seccomp_flag_parsing(args, expected):
    assert oci_seccomp_enabled(args) is expected


def test_runc_needs_nothing_from_the_daemon():
    assert check(info(), "runc") == []
    assert check({}, "runc") == []


def test_runc_warns_when_the_daemon_defaults_to_gvisor():
    (warning,) = check(info({"path": "runsc"}, default="runsc"), "runc")
    assert 'runtime = "runsc"' in warning


def test_missing_runsc_is_an_error_with_instructions():
    with pytest.raises(RuntimeCheckError, match="no runsc runtime") as error:
        check(info(), "runsc")
    message = str(error.value)
    assert "available: io.containerd.runc.v2, runc" in message
    assert "runsc install -- --oci-seccomp" in message and "gvisor.dev" in message
    with pytest.raises(RuntimeCheckError, match="available: none"):
        check({}, "runsc")


def test_runsc_without_oci_seccomp_is_an_error():
    with pytest.raises(RuntimeCheckError, match="without --oci-seccomp"):
        check(info({"path": "/usr/local/bin/runsc"}), "runsc")
    with pytest.raises(RuntimeCheckError, match="without --oci-seccomp"):
        check(info({"path": "runsc", "runtimeArgs": ["--oci-seccomp=false"]}), "runsc")


def test_runsc_with_oci_seccomp_passes():
    entry = {"path": "/usr/local/bin/runsc", "runtimeArgs": ["--oci-seccomp", "--platform=kvm"]}
    assert check(info(entry), "runsc") == []


def test_runsc_as_a_containerd_shim_cannot_be_confirmed():
    (warning,) = check(info({"runtimeType": "io.containerd.runsc.v1"}), "runsc")
    assert "cannot confirm" in warning and "verify" in warning
