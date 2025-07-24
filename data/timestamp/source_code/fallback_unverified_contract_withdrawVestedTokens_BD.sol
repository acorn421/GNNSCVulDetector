/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawVestedTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a vesting mechanism. The contract relies on block.timestamp to calculate vested amounts, which can be manipulated by miners within certain bounds. An attacker who is a miner could potentially manipulate timestamps to accelerate their vesting schedule. The vulnerability is stateful and multi-transaction because: 1) A vesting schedule must first be created via createVestingSchedule(), 2) The attacker must wait and potentially manipulate timestamps across multiple blocks, 3) Multiple calls to withdrawVestedTokens() are needed to fully exploit the accumulated vesting amounts, 4) The vulnerability requires persistent state changes in the VestingSchedule struct across multiple transactions.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Yum is ERC20Interface {
    uint8 public constant decimals = 18;
    uint256 public constant INITIAL_SUPPLY = 3000000 * (10 ** uint256(decimals));
    string public constant symbol = "YUM";
    string public constant name = "YUM Token";
    uint256 public constant totalSupply = INITIAL_SUPPLY;
    
    // Owner is the address controlled by FilletX.
    address constant owner = 0x045da370c3c0A1A55501F3B78Becc78a084CC488;

    // Account represents a user account.
    struct Account {
        // Balance is the user balance. 
        uint256 balance;
        // Addr is the address of the account.
        address addr;
        // Enabled is true if the user is able to transfer funds.
        bool enabled;
    }

    // Accounts holds user accounts.
    mapping(address => Account) accounts;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vesting schedule for locked tokens
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 releasedAmount;
        uint256 startTime;
        uint256 duration;
        bool isActive;
    }
    
    mapping(address => VestingSchedule) public vestingSchedules;
    
    // Create a vesting schedule for an address
    function createVestingSchedule(address _beneficiary, uint256 _amount, uint256 _duration) public {
        assert(msg.sender == owner);
        require(_beneficiary != address(0));
        require(_amount > 0);
        require(_duration > 0);
        require(accounts[owner].balance >= _amount);
        
        // Transfer tokens to vesting contract control
        accounts[owner].balance -= _amount;
        
        vestingSchedules[_beneficiary] = VestingSchedule({
            totalAmount: _amount,
            releasedAmount: 0,
            startTime: block.timestamp,
            duration: _duration,
            isActive: true
        });
    }
    
    // Withdraw vested tokens - vulnerable to timestamp manipulation
    function withdrawVestedTokens() public {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        require(schedule.isActive);
        require(schedule.releasedAmount < schedule.totalAmount);
        
        // Vulnerable: relies on block.timestamp which can be manipulated by miners
        uint256 elapsedTime = block.timestamp - schedule.startTime;
        uint256 vestedAmount;
        
        if (elapsedTime >= schedule.duration) {
            vestedAmount = schedule.totalAmount;
        } else {
            vestedAmount = (schedule.totalAmount * elapsedTime) / schedule.duration;
        }
        
        uint256 withdrawableAmount = vestedAmount - schedule.releasedAmount;
        require(withdrawableAmount > 0);
        
        schedule.releasedAmount += withdrawableAmount;
        accounts[msg.sender].balance += withdrawableAmount;
        
        if (schedule.releasedAmount >= schedule.totalAmount) {
            schedule.isActive = false;
        }
        
        Transfer(address(0), msg.sender, withdrawableAmount);
    }
    // === END FALLBACK INJECTION ===

    // Constructor.
    function Yum() public {
        accounts[owner] = Account({
          addr: owner,
          balance: INITIAL_SUPPLY,
          enabled: true
        });
    }

    // Get balace of an account.
    function balanceOf(address _owner) public constant returns (uint balance) {
        return accounts[_owner].balance;
    }
    
    // Set enabled status of the account.
    function setEnabled(address _addr, bool _enabled) public {
        assert(msg.sender == owner);
        if (accounts[_addr].enabled != _enabled) {
            accounts[_addr].enabled = _enabled;
        }
    }
    
    // Transfer funds.
    function transfer(address _to, uint256 _amount) public returns (bool) {
        require(_to != address(0));
        require(_amount <= accounts[msg.sender].balance);
        // Enable the receiver if the sender is the exchange.
        if (msg.sender == owner && !accounts[_to].enabled) {
            accounts[_to].enabled = true;
        }
        if (
            // Check that the sender's account is enabled.
            accounts[msg.sender].enabled
            // Check that the receiver's account is enabled.
            && accounts[_to].enabled
            // Check that the sender has sufficient balance.
            && accounts[msg.sender].balance >= _amount
            // Check that the amount is valid.
            && _amount > 0
            // Check for overflow.
            && accounts[_to].balance + _amount > accounts[_to].balance) {
                // Credit the sender.
                accounts[msg.sender].balance -= _amount;
                // Debit the receiver.
                accounts[_to].balance += _amount;
                Transfer(msg.sender, _to, _amount);
                return true;
        }
        return false;
    }
}