/*
 * ===== SmartInject Injection Details =====
 * Function      : timedTransfer
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
 * This vulnerability introduces timestamp dependence through time-locked transfers. The exploit requires multiple transactions: first scheduling a transfer with scheduleTransfer() or receiving a timedTransfer(), then waiting for the timestamp condition, and finally executing with executeScheduledTransfer(). Miners can manipulate block timestamps within acceptable bounds to potentially execute transfers earlier than intended, especially problematic for time-sensitive financial operations. The vulnerability persists across multiple blocks and requires accumulated state changes in the mapping variables.
 */
pragma solidity ^0.4.24;
contract EIP20Interface {
    uint256 public totalSupply;
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract ECT is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mappings must be declared at contract scope, not inside constructor
    mapping (address => uint256) public scheduledTransfers;
    mapping (address => address) public transferRecipients;
    mapping (address => uint256) public transferDeadlines;
    // === END DECLARE FALLBACK MAPPINGS ===

    function ECT (
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        totalSupply = _initialAmount*10**uint256(_decimalUnits);     // Update total supply
        balances[msg.sender] = totalSupply;                          // Update total supply
        name = _tokenName;                                           // Set the name for display purposes
        decimals = _decimalUnits;                                    // Amount of decimals for display purposes
        symbol = _tokenSymbol;                                       // Set the symbol for display purposes
    }

    function scheduleTransfer(address _to, uint256 _value, uint256 _delay) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(_delay > 0);
        
        scheduledTransfers[msg.sender] = _value;
        transferRecipients[msg.sender] = _to;
        transferDeadlines[msg.sender] = now + _delay;
        
        return true;
    }
    
    function executeScheduledTransfer() public returns (bool success) {
        require(scheduledTransfers[msg.sender] > 0);
        require(now >= transferDeadlines[msg.sender]);
        require(balances[msg.sender] >= scheduledTransfers[msg.sender]);
        
        uint256 amount = scheduledTransfers[msg.sender];
        address recipient = transferRecipients[msg.sender];
        
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
        
        scheduledTransfers[msg.sender] = 0;
        transferRecipients[msg.sender] = address(0);
        transferDeadlines[msg.sender] = 0;
        
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }
    
    function timedTransfer(address _to, uint256 _value, uint256 _unlockTime) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(_unlockTime > now);
        
        balances[msg.sender] -= _value;
        scheduledTransfers[_to] = _value;
        transferDeadlines[_to] = _unlockTime;
        
        return true;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
