#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>

class ICounterStore
{
public:
    virtual ~ICounterStore() = default;

    [[nodiscard]] virtual std::optional<std::uint64_t> load() const = 0;
    [[nodiscard]] virtual bool save(std::uint64_t value) = 0;
};

class FileCounterStore final : public ICounterStore
{
private:
    std::filesystem::path _path;

public:
    explicit FileCounterStore(std::filesystem::path path);

    [[nodiscard]] std::optional<std::uint64_t> load() const override;
    [[nodiscard]] bool save(std::uint64_t value) override;
};

class InMemoryCounterStore final : public ICounterStore
{
private:
    std::uint64_t _value = 0;
    bool _failSaves = false;
    bool _unreadable = false;

public:
    [[nodiscard]] std::optional<std::uint64_t> load() const override;
    [[nodiscard]] bool save(std::uint64_t value) override;

    std::uint64_t value() const { return _value; }
    void setFailSaves(bool fail) { _failSaves = fail; }
    void setUnreadable(bool unreadable) { _unreadable = unreadable; }
};
