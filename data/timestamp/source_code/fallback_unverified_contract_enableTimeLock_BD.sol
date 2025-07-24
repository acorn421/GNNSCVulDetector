/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Multi-transaction timestamp dependence vulnerability where miners can manipulate block.timestamp to bypass time locks. The vulnerability requires: 1) First transaction to enableTimeLock(), 2) Second transaction to requestWithdrawal(), 3) Third transaction to executeWithdrawal() where timestamp manipulation allows premature execution. The state persists across transactions through timeLockEndTime and pendingWithdrawals mappings.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract YoungToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === Move time lock state variables to contract scope ===
    mapping (address => uint256) public timeLockEndTime;
    mapping (address => uint256) public pendingWithdrawals;
    uint256 public constant LOCK_DURATION = 24 hours;
    // === End move ===

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    
    event TimeLockEnabled(address indexed user, uint256 lockEndTime);
    event WithdrawalRequested(address indexed user, uint256 amount);
    event WithdrawalExecuted(address indexed user, uint256 amount);

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function enableTimeLock() public {
        // Enable time lock for sender - uses block.timestamp which miners can manipulate
        timeLockEndTime[msg.sender] = block.timestamp + LOCK_DURATION;
        emit TimeLockEnabled(msg.sender, timeLockEndTime[msg.sender]);
    }
    
    function requestWithdrawal(uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        require(timeLockEndTime[msg.sender] != 0, "Time lock not enabled");
        // First transaction: request withdrawal (state change)
        pendingWithdrawals[msg.sender] = _amount;
        emit WithdrawalRequested(msg.sender, _amount);
    }
    
    function executeWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        // VULNERABILITY: Miners can manipulate block.timestamp to bypass time lock
        // This requires multiple transactions and state persistence
        require(block.timestamp >= timeLockEndTime[msg.sender], "Time lock still active");
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        // Execute the withdrawal by burning tokens
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit WithdrawalExecuted(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]); 
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;          
        totalSupply -= _value;                     
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);             
        require(_value <= allowance[_from][msg.sender]);   
        balanceOf[_from] -= _value;                        
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
