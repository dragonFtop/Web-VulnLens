(function () {
  "use strict";

  async function requestJson(url, options) {
    let response;
    try {
      response = await fetch(url, options);
    } catch (error) {
      throw new Error("无法连接服务，请确认服务正在运行");
    }
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (error) {
        data = null;
      }
    }
    if (!response.ok) {
      const detail = data && data.error ? data.error : null;
      const message = detail && detail.message ? detail.message : "请求失败（HTTP " + response.status + "）";
      const code = detail && detail.code ? "（" + detail.code + "）" : "";
      throw new Error(message + code);
    }
    if (data === null) {
      throw new Error("服务返回了无法解析的响应");
    }
    return data;
  }

  function initTimestamps() {
    document.querySelectorAll("[data-utc]").forEach(function (element) {
      const raw = element.getAttribute("data-utc");
      if (!raw) {
        return;
      }
      const date = new Date(raw);
      if (Number.isNaN(date.getTime())) {
        return;
      }
      element.textContent = date.toLocaleString("zh-CN", { hour12: false });
      element.title = raw;
    });
  }

  function highlightElementSafe(element) {
    if (!window.hljs || !element) {
      return;
    }
    try {
      window.hljs.highlightElement(element);
    } catch (error) {
      // 单行高亮失败不应影响页面展示。
    }
  }

  function initHighlights() {
    document.querySelectorAll("[data-highlight='1']").forEach(function (container) {
      const elements = container.querySelectorAll(".code-text");
      if (elements.length > 800) {
        return;
      }
      elements.forEach(highlightElementSafe);
    });
    const patched = document.getElementById("patched-code");
    if (patched) {
      highlightElementSafe(patched);
    }
  }

  function showTab(selector) {
    const button = document.querySelector(selector);
    if (!button) {
      return;
    }
    if (window.bootstrap && window.bootstrap.Tab) {
      window.bootstrap.Tab.getOrCreateInstance(button).show();
    } else {
      button.click();
    }
  }

  function flash(element) {
    element.classList.add("finding-flash");
    window.setTimeout(function () {
      element.classList.remove("finding-flash");
    }, 1600);
  }

  function initJumpTargets() {
    document.querySelectorAll("[data-jump-target]").forEach(function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        const selector = link.getAttribute("data-jump-target");
        if (!selector) {
          return;
        }
        showTab("[data-bs-target='#tab-source']");
        window.setTimeout(function () {
          const target = document.querySelector(selector);
          if (target) {
            target.scrollIntoView({ behavior: "smooth", block: "center" });
            flash(target);
          }
        }, 120);
      });
    });
  }

  function initCodeLineClicks() {
    document.querySelectorAll(".code-row[data-finding-ids] .code-ln").forEach(function (link) {
      link.addEventListener("click", function (event) {
        const row = link.closest(".code-row");
        const ids = (row.getAttribute("data-finding-ids") || "").split(",").filter(Boolean);
        if (!ids.length) {
          return;
        }
        const card = document.getElementById("finding-" + ids[0]);
        if (!card) {
          return;
        }
        event.preventDefault();
        showTab("[data-bs-target='#tab-findings']");
        window.setTimeout(function () {
          card.scrollIntoView({ behavior: "smooth", block: "center" });
          flash(card);
        }, 120);
      });
    });
  }

  function createScanUi() {
    const panel = document.getElementById("scan-panel");
    const spinner = document.getElementById("scan-spinner");
    const text = document.getElementById("scan-status-text");
    const progress = document.getElementById("scan-progress-wrap");
    const errorBox = document.getElementById("scan-error");
    if (!panel || !spinner || !text || !progress || !errorBox) {
      return null;
    }
    return {
      start: function (message) {
        panel.classList.remove("d-none");
        spinner.hidden = false;
        progress.hidden = false;
        errorBox.classList.add("d-none");
        errorBox.textContent = "";
        text.textContent = message;
      },
      update: function (message) {
        text.textContent = message;
      },
      fail: function (message) {
        spinner.hidden = true;
        progress.hidden = true;
        text.textContent = "无法完成扫描";
        errorBox.textContent = message;
        errorBox.classList.remove("d-none");
      },
      done: function (message) {
        spinner.hidden = true;
        progress.hidden = true;
        text.textContent = message;
      },
    };
  }

  function pollJob(jobId, ui, onFailure) {
    let attempts = 0;
    function tick() {
      attempts += 1;
      requestJson("/api/scans/" + encodeURIComponent(jobId))
        .then(function (job) {
          const stage = job.stage_display || job.status_display || "";
          ui.update(job.status_display + (stage ? " · " + stage : ""));
          if (job.status === "DONE") {
            ui.done("扫描完成，正在打开结果…");
            window.location.assign("/scans/" + encodeURIComponent(jobId));
            return;
          }
          if (job.status === "FAILED") {
            ui.fail(job.error || "扫描失败，请查看服务端日志");
            if (onFailure) {
              onFailure();
            }
            return;
          }
          if (attempts >= 300) {
            ui.fail("扫描时间过长，请前往历史记录查看任务状态。");
            if (onFailure) {
              onFailure();
            }
            return;
          }
          window.setTimeout(tick, 1000);
        })
        .catch(function (error) {
          ui.update("查询进度失败：" + error.message + "，正在重试…");
          if (attempts >= 300) {
            ui.fail("无法查询任务进度，请刷新页面或查看历史记录。");
            if (onFailure) {
              onFailure();
            }
            return;
          }
          window.setTimeout(tick, 1500);
        });
    }
    tick();
  }

  function initScanForms() {
    const ui = createScanUi();
    const codeForm = document.getElementById("code-form");
    if (codeForm && ui) {
      codeForm.addEventListener("submit", function (event) {
        event.preventDefault();
        const input = document.getElementById("code-file");
        const button = document.getElementById("code-submit");
        const file = input && input.files && input.files[0];
        if (!file) {
          ui.start("请选择文件");
          ui.fail("请选择 .py / .php / .js 代码文件");
          return;
        }
        const allowed = [".py", ".php", ".js"];
        const suffix = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
        if (allowed.indexOf(suffix) === -1) {
          ui.start("文件类型不支持");
          ui.fail("仅支持 .py / .php / .js 文件");
          return;
        }
        button.disabled = true;
        ui.start("正在上传文件…");
        const formData = new FormData();
        formData.append("file", file, file.name);
        requestJson("/api/upload", { method: "POST", body: formData })
          .then(function (uploaded) {
            ui.update("上传完成，正在创建扫描任务…");
            return requestJson("/api/scans", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ input_type: "code", file_id: uploaded.file_id }),
            });
          })
          .then(function (scan) {
            ui.update("任务已创建，正在分析…");
            pollJob(scan.job_id, ui, function () {
              button.disabled = false;
            });
          })
          .catch(function (error) {
            ui.fail(error.message);
            button.disabled = false;
          });
      });
    }

    const httpForm = document.getElementById("http-form");
    if (httpForm && ui) {
      httpForm.addEventListener("submit", function (event) {
        event.preventDefault();
        const input = document.getElementById("http-input");
        const button = document.getElementById("http-submit");
        const raw = input ? input.value.trim() : "";
        if (!raw) {
          ui.start("请粘贴请求");
          ui.fail("HTTP 请求内容不能为空");
          return;
        }
        button.disabled = true;
        ui.start("正在创建请求分析任务…");
        requestJson("/api/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input_type: "http", raw_http: raw }),
        })
          .then(function (scan) {
            ui.update("任务已创建，正在分析…");
            pollJob(scan.job_id, ui, function () {
              button.disabled = false;
            });
          })
          .catch(function (error) {
            ui.fail(error.message);
            button.disabled = false;
          });
      });
    }
  }

  function initRepairButtons() {
    document.querySelectorAll(".repair-btn").forEach(function (button) {
      button.addEventListener("click", function () {
        const findingId = button.getAttribute("data-finding-id");
        if (!findingId) {
          return;
        }
        const status = document.getElementById("repair-status-" + findingId);
        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = "生成中…";
        if (status) {
          status.textContent = "正在调用模型，最长约 90 秒…";
          status.classList.remove("text-danger");
        }
        requestJson("/api/findings/" + encodeURIComponent(findingId) + "/repair", {
          method: "POST",
        })
          .then(function (repair) {
            if (status) {
              status.textContent = "修复已生成，正在打开详情…";
            }
            window.location.assign("/repairs/" + encodeURIComponent(repair.repair_id));
          })
          .catch(function (error) {
            if (status) {
              status.textContent = error.message;
              status.classList.add("text-danger");
            }
            button.disabled = false;
            button.textContent = originalText;
          });
      });
    });
  }

  function initJobLive() {
    const live = document.getElementById("job-live");
    if (!live) {
      return;
    }
    const jobId = live.getAttribute("data-job-id");
    if (!jobId) {
      return;
    }
    let attempts = 0;
    function tick() {
      attempts += 1;
      requestJson("/api/scans/" + encodeURIComponent(jobId))
        .then(function (job) {
          const text = document.getElementById("job-live-text");
          if (text) {
            text.textContent = job.stage_display || job.status_display;
          }
          if (job.status === "DONE" || job.status === "FAILED") {
            window.location.reload();
            return;
          }
        })
        .catch(function () {
          // 网络波动时静默重试。
        });
      if (attempts < 300) {
        window.setTimeout(tick, 1500);
      }
    }
    window.setTimeout(tick, 1000);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTimestamps();
    initHighlights();
    initJumpTargets();
    initCodeLineClicks();
    initScanForms();
    initRepairButtons();
    initJobLive();
  });
})();
