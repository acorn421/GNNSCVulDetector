/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimedVesting
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a vesting system. The vulnerability is stateful and multi-transaction because: 1) A vesting schedule must first be created using createTimedVesting(), which sets the startTime using 'now' (block.timestamp), 2) The beneficiary must then call releaseVestedTokens() in subsequent transactions to claim tokens, 3) The amount released depends on the time elapsed calculation using 'now', which miners can manipulate, 4) The vesting state persists between transactions and accumulates released amounts. A malicious miner can manipulate block timestamps to either accelerate vesting (by setting future timestamps) or delay it, affecting the amount of tokens that can be released in each transaction.
 */
pragma solidity ^0.4.16;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}

contract SPIN is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vesting schedule tracking
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 releasedAmount;
        uint256 startTime;
        uint256 duration;
        bool active;
    }
    
    mapping(address => VestingSchedule) public vestingSchedules;
    
    event VestingCreated(address indexed beneficiary, uint256 amount, uint256 duration);
    event VestingReleased(address indexed beneficiary, uint256 amount);
    
    /* Create a vesting schedule for token release */
    function createTimedVesting(address _beneficiary, uint256 _amount, uint256 _duration) public {
        require(_beneficiary != 0x0);
        require(_amount > 0);
        require(_duration > 0);
        require(balanceOf[msg.sender] >= _amount);
        require(!vestingSchedules[_beneficiary].active);
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        
        vestingSchedules[_beneficiary] = VestingSchedule({
            totalAmount: _amount,
            releasedAmount: 0,
            startTime: now, // Vulnerable to timestamp manipulation
            duration: _duration,
            active: true
        });
        
        VestingCreated(_beneficiary, _amount, _duration);
    }
    
    /* Release vested tokens based on time elapsed */
    function releaseVestedTokens() public {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        require(schedule.active);
        require(now >= schedule.startTime); // Vulnerable to timestamp manipulation
        
        uint256 elapsedTime = now - schedule.startTime; // Vulnerable calculation
        uint256 vestedAmount;
        
        if (elapsedTime >= schedule.duration) {
            vestedAmount = schedule.totalAmount;
        } else {
            vestedAmount = SafeMath.safeDiv(SafeMath.safeMul(schedule.totalAmount, elapsedTime), schedule.duration);
        }
        
        uint256 releasableAmount = SafeMath.safeSub(vestedAmount, schedule.releasedAmount);
        require(releasableAmount > 0);
        
        schedule.releasedAmount = SafeMath.safeAdd(schedule.releasedAmount, releasableAmount);
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], releasableAmount);
        
        if (schedule.releasedAmount >= schedule.totalAmount) {
            schedule.active = false;
        }
        
        VestingReleased(msg.sender, releasableAmount);
    }
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SPIN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);                        // Update total supply
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
    returns (bool success) {
        require(_value > 0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) public {
        require(msg.sender == owner);
        owner.transfer(amount);
    }

    // can accept ether
    function() public payable {
    }
}
