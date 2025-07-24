/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimelockedTransfer
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
 * This injection adds a multi-transaction timestamp dependence vulnerability through timelocked transfers. The vulnerability requires: 1) First transaction to create a timelocked transfer via startTimelockedTransfer(), 2) State persistence between transactions storing the unlock time, 3) Second transaction to execute or cancel the transfer based on timestamp comparison. Miners can manipulate block timestamps within acceptable bounds to either execute transfers early or prevent cancellation, affecting the intended time-based security mechanism.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timelocked transfer data structure and storage
    struct TimelockedTransfer {
        address to;
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping(address => TimelockedTransfer) public timelockedTransfers;
    
    event TimelockedTransferCreated(address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event TimelockedTransferExecuted(address indexed from, address indexed to, uint256 amount);
    // === END FALLBACK INJECTION ===

    function HKTToken(
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
    function startTimelockedTransfer(address _to, uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration > 0);
        require(!timelockedTransfers[msg.sender].executed || timelockedTransfers[msg.sender].unlockTime < now);
        
        // Lock the tokens by reducing sender's balance
        balanceOf[msg.sender] -= _amount;
        
        // Create timelocked transfer - vulnerable to timestamp manipulation
        timelockedTransfers[msg.sender] = TimelockedTransfer({
            to: _to,
            amount: _amount,
            unlockTime: now + _lockDuration,
            executed: false
        });
        
        TimelockedTransferCreated(msg.sender, _to, _amount, now + _lockDuration);
        return true;
    }
    
    function executeTimelockedTransfer() public returns (bool success) {
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender];
        require(transfer.amount > 0);
        require(!transfer.executed);
        
        // Vulnerable: miners can manipulate timestamp to execute transfers early
        require(now >= transfer.unlockTime);
        
        // Execute the transfer
        balanceOf[transfer.to] += transfer.amount;
        transfer.executed = true;
        
        Transfer(msg.sender, transfer.to, transfer.amount);
        TimelockedTransferExecuted(msg.sender, transfer.to, transfer.amount);
        return true;
    }
    
    function cancelTimelockedTransfer() public returns (bool success) {
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender];
        require(transfer.amount > 0);
        require(!transfer.executed);
        
        // Vulnerable: miners can manipulate timestamp to prevent cancellation
        require(now < transfer.unlockTime);
        
        // Return tokens to sender
        balanceOf[msg.sender] += transfer.amount;
        transfer.executed = true;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
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
        Approval(msg.sender, _spender, _value);
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
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
