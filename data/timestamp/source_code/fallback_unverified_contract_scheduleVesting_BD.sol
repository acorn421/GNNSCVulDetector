/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleVesting
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue through token vesting functionality. The vulnerability requires multiple transactions to exploit: (1) Owner schedules vesting with scheduleVesting(), (2) Owner can later manipulate the vesting schedule using adjustVestingSchedule() to change start times, (3) Users claim tokens with claimVesting() based on manipulated timestamps. The vulnerability persists across transactions through state variables (vestingStart, vestingAmount, etc.) and allows the owner to manipulate when tokens become available by adjusting timestamps after vesting is scheduled. This creates unfair advantages and breaks the intended vesting mechanism through timestamp manipulation across multiple transaction calls.
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract PIN is owned {
    /* Public variables of the token */
    string public standard = 'PIN 0.1';
    string public name;
    string public symbol;
    uint8 public decimals = 0;
    uint256 public totalSupply;
    bool public locked;
    uint256 public icoSince;
    uint256 public icoTill;

     /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event IcoFinished();
    event Burn(address indexed from, uint256 value);

    uint256 public buyPrice = 0.01 ether;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vesting mappings and events - moved out of constructor
    mapping (address => uint256) public vestingAmount;
    mapping (address => uint256) public vestingStart;
    mapping (address => uint256) public vestingDuration;
    mapping (address => uint256) public vestingClaimed;
    
    event VestingScheduled(address indexed beneficiary, uint256 amount, uint256 startTime, uint256 duration);
    event VestingClaimed(address indexed beneficiary, uint256 amount);
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function PIN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint256 _icoSince,
        uint256 _icoTill,
        uint durationInDays
    ) public {
        totalSupply = initialSupply;

        balanceOf[this] = totalSupply / 100 * 22;             // Give the smart contract 22% of initial tokens
        name = tokenName;                                     // Set the name for display purposes
        symbol = tokenSymbol;                                 // Set the symbol for display purposes

        balanceOf[msg.sender] = totalSupply / 100 * 78;       // Give remaining total supply to contract owner, will be destroyed

        Transfer(this, msg.sender, balanceOf[msg.sender]);

        if(_icoSince == 0 && _icoTill == 0) {
            icoSince = now;
            icoTill = now + durationInDays * 35 days;
        }
        else {
            icoSince = _icoSince;
            icoTill = _icoTill;
        }
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleVesting(address _beneficiary, uint256 _amount, uint256 _startTime, uint256 _duration) public onlyOwner {
        require(_beneficiary != address(0));
        require(_amount > 0);
        require(_duration > 0);
        require(balanceOf[this] >= _amount);
        
        vestingAmount[_beneficiary] = _amount;
        vestingStart[_beneficiary] = _startTime;
        vestingDuration[_beneficiary] = _duration;
        vestingClaimed[_beneficiary] = 0;
        
        VestingScheduled(_beneficiary, _amount, _startTime, _duration);
    }
    
    function claimVesting() public {
        require(vestingAmount[msg.sender] > 0);
        require(now >= vestingStart[msg.sender]);
        
        uint256 totalVested = vestingAmount[msg.sender];
        uint256 elapsedTime = now - vestingStart[msg.sender];
        uint256 vestedAmount;
        
        if (elapsedTime >= vestingDuration[msg.sender]) {
            vestedAmount = totalVested;
        } else {
            vestedAmount = (totalVested * elapsedTime) / vestingDuration[msg.sender];
        }
        
        uint256 claimableAmount = vestedAmount - vestingClaimed[msg.sender];
        require(claimableAmount > 0);
        require(balanceOf[this] >= claimableAmount);
        
        vestingClaimed[msg.sender] += claimableAmount;
        balanceOf[this] -= claimableAmount;
        balanceOf[msg.sender] += claimableAmount;
        
        Transfer(this, msg.sender, claimableAmount);
        VestingClaimed(msg.sender, claimableAmount);
    }
    
    function adjustVestingSchedule(address _beneficiary, uint256 _newStartTime) public onlyOwner {
        require(vestingAmount[_beneficiary] > 0);
        require(_newStartTime > 0);
        // Vulnerable: Owner can manipulate vesting schedule after it's set
        vestingStart[_beneficiary] = _newStartTime;
    }
    // === END FALLBACK INJECTION ===

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(locked == false);                            // Check if smart contract is locked
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(locked == false);                            // Check if smart contract is locked
        require(_value > 0);
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function buy(uint256 ethers, uint256 time) internal {
        require(locked == false);                            // Check if smart contract is locked
        require(time >= icoSince && time <= icoTill);        // check for ico dates
        require(ethers > 0);                                 // check if ethers is greater than zero
        uint amount = ethers / buyPrice;
        require(balanceOf[this] >= amount);                  // check if smart contract has sufficient number of tokens
        balanceOf[msg.sender] += amount;
        balanceOf[this] -= amount;
        Transfer(this, msg.sender, amount);
    }

    function () payable public {
        buy(msg.value, now);
    }

    function internalIcoFinished(uint256 time) internal returns (bool) {
        if(time > icoTill) {
            uint256 unsoldTokens = balanceOf[this];
            balanceOf[owner] += unsoldTokens;
            balanceOf[this] = 0;
            Transfer(this, owner, unsoldTokens);
            IcoFinished();
            return true;
        }
        return false;
    }

    function icoFinished() public onlyOwner {
        internalIcoFinished(now);
    }

    function transferEthers() public onlyOwner {
        owner.transfer(this.balance);
    }

    function setBuyPrice(uint256 _buyPrice) public onlyOwner {
        buyPrice = _buyPrice;
    }

    function setLocked(bool _locked) public onlyOwner {
        locked = _locked;
    }

    function burn(uint256 _value) public onlyOwner returns (bool success) {
        require (balanceOf[msg.sender] > _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
}