/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a stateful timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability exists in the time-locked token system where: 1) A user must first call initiateTimeLock() to start the lock period, 2) The system relies on 'now' (block.timestamp) for time calculations, 3) A malicious miner can manipulate timestamps to claim tokens early by calling claimTimeLock() before the intended lock period expires. The vulnerability is stateful because it requires the timelock state to be established in one transaction and then exploited in subsequent transactions. The state persists between transactions through the mapping variables that track lock times and durations.
 */
pragma solidity ^0.4.19;

/// @title  MedicalChain token presale - https://medicalchain.com/ (MED) - crowdfunding code
/// Whitepaper:
///  https://medicalchain.com/Medicalchain-Whitepaper-EN.pdf

contract MedicalChainToken {
    string public name = "MedToken";
    string public symbol = "MED";
    uint8 public constant decimals = 18;  
    address public owner;

    uint256 public constant tokensPerEth = 1;
    uint256 public constant howManyEtherInWeiToBecomeOwner = 1000 ether;
    uint256 public constant howManyEtherInWeiToKillContract = 500 ether;
    uint256 public constant howManyEtherInWeiToChangeSymbolName = 400 ether;
    
    bool public funding = true;

    // The current total token supply.
    uint256 totalTokens = 1000;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Migrate(address indexed _from, address indexed _to, uint256 _value);
    event Refund(address indexed _from, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked transfer system for medical data access
    mapping(address => uint256) public timeLockStart;
    mapping(address => uint256) public timeLockDuration;
    mapping(address => uint256) public lockedTokens;
    mapping(address => address) public lockBeneficiary;

    uint256 public constant MIN_LOCK_DURATION = 1 hours;
    uint256 public constant MAX_LOCK_DURATION = 365 days;

    event TimeLockInitiated(address indexed user, uint256 amount, uint256 duration);
    event TimeLockClaimed(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    function MedicalChainToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    /// @notice Initiate a time-locked token transfer for medical data access
    /// @param _amount Amount of tokens to lock
    /// @param _duration Duration in seconds to lock tokens
    /// @param _beneficiary Address that can claim tokens after lock period
    function initiateTimeLock(uint256 _amount, uint256 _duration, address _beneficiary) external {
        require(_amount > 0, "Amount must be greater than 0");
        require(_duration >= MIN_LOCK_DURATION && _duration <= MAX_LOCK_DURATION, "Invalid duration");
        require(_beneficiary != address(0), "Invalid beneficiary");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        require(timeLockStart[msg.sender] == 0, "Active timelock exists");
        
        // Transfer tokens to contract control
        balances[msg.sender] -= _amount;
        lockedTokens[msg.sender] = _amount;
        timeLockStart[msg.sender] = now; // Vulnerable to timestamp manipulation
        timeLockDuration[msg.sender] = _duration;
        lockBeneficiary[msg.sender] = _beneficiary;
        
        TimeLockInitiated(msg.sender, _amount, _duration);
    }
    
    /// @notice Claim time-locked tokens after lock period expires
    function claimTimeLock() external {
        require(timeLockStart[msg.sender] > 0, "No active timelock");
        require(lockedTokens[msg.sender] > 0, "No tokens to claim");
        
        // Vulnerable: Miners can manipulate timestamp to claim early
        require(now >= timeLockStart[msg.sender] + timeLockDuration[msg.sender], "Lock period not expired");
        
        uint256 amount = lockedTokens[msg.sender];
        address beneficiary = lockBeneficiary[msg.sender];
        
        // Reset timelock state
        timeLockStart[msg.sender] = 0;
        timeLockDuration[msg.sender] = 0;
        lockedTokens[msg.sender] = 0;
        lockBeneficiary[msg.sender] = address(0);
        
        // Transfer tokens to beneficiary
        balances[beneficiary] += amount;
        
        TimeLockClaimed(msg.sender, amount);
        Transfer(msg.sender, beneficiary, amount);
    }
    
    /// @notice Extend an existing timelock duration (for medical data access extensions)
    function extendTimeLock(uint256 _additionalDuration) external {
        require(timeLockStart[msg.sender] > 0, "No active timelock");
        require(_additionalDuration > 0, "Additional duration must be positive");
        
        // Vulnerable: Extension based on current timestamp
        uint256 currentExpiry = timeLockStart[msg.sender] + timeLockDuration[msg.sender];
        require(now < currentExpiry, "Timelock already expired");
        
        timeLockDuration[msg.sender] += _additionalDuration;
        
        // Ensure total duration doesn't exceed maximum
        require(timeLockDuration[msg.sender] <= MAX_LOCK_DURATION, "Total duration exceeds maximum");
    }

    function changeNameSymbol(string _name, string _symbol) payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            name = _name;
            symbol = _symbol;
        }
    }
    
    
    function changeOwner (address _newowner) payable external
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            owner.transfer(msg.value);
            owner.transfer(this.balance);
            owner=_newowner;
        }
    }

    function killContract () payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToKillContract)
        {
            selfdestruct(owner);
        }
    }
    /// @notice Transfer `_value` tokens from sender's account
    /// `msg.sender` to provided account address `_to`.
    /// @notice This function is disabled during the funding.
    /// @dev Required state: Operational
    /// @param _to The address of the tokens recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
        var senderBalance = balances[msg.sender];
        if (senderBalance >= _value && _value > 0) {
            senderBalance -= _value;
            balances[msg.sender] = senderBalance;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
    }
    

    function totalSupply() external constant returns (uint256) {
        return totalTokens;
    }

    function balanceOf(address _owner) external constant returns (uint256) {
        return balances[_owner];
    }


    function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) public returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             return true;
         } else {
             return false;
         }
  }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         
         return true;
     }
// Crowdfunding:

    /// @notice Create tokens when funding is active.
    /// @dev Required state: Funding Active
    /// @dev State transition: -> Funding Success (only if cap reached)
    function () payable external {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        var numTokens = msg.value * (1000.0/totalTokens);
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}
