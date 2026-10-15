#pragma once
#include <filesystem>
#include <optional>

#include "common/Checkpoint.h"

class AnchorStore
{
public:
    virtual ~AnchorStore() = default;
    [[nodiscard]] virtual bool save(const Checkpoint& cp) = 0;
    virtual std::optional<Checkpoint> load() const = 0;
};

class FileAnchorStore final : public AnchorStore
{
private:
    std::filesystem::path _path;

public:
    explicit FileAnchorStore(std::filesystem::path path);

    [[nodiscard]] bool save(const Checkpoint& cp) override;
    std::optional<Checkpoint> load() const override;
};

class InMemoryAnchorStore final : public AnchorStore
{
private:
    std::optional<Checkpoint> _cp;
    bool _failSaves = false;

public:
    [[nodiscard]] bool save(const Checkpoint& cp) override;
    std::optional<Checkpoint> load() const override { return _cp; }

    void setFailSaves(bool fail) { _failSaves = fail; }
    void clear() { _cp.reset(); }
};
