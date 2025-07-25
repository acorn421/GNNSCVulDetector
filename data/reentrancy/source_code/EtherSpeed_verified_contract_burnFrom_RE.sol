/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external callback to `ITokenHolder(_from).onTokensBurned(_value)` before state updates. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **Transaction 1**: Attacker calls burnFrom() with their malicious contract as `_from`
 * 2. **Reentrancy Point**: During the callback, the malicious contract can re-enter burnFrom() while the original state (balances, allowance, totalSupply) remains unchanged
 * 3. **Transaction 2+**: The attacker can burn tokens multiple times using the same allowance and balance values before they are decremented
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction establishes the callback and initial state
 * - Subsequent re-entrant calls exploit the unchanged state
 * - The attacker can drain tokens beyond their actual allowance across multiple nested calls
 * - State accumulation across the call stack enables the exploit
 * 
 * This is realistic as many token contracts implement holder notification patterns, but placing the callback before state updates violates the checks-effects-interactions pattern and creates a classic reentrancy vulnerability.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Definition for ITokenHolder interface needed for callback
interface ITokenHolder {
    function onTokensBurned(uint256 _value) external;
}

contract EtherSpeed {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 public funds;
    address public director;
    bool public saleClosed;
    bool public directorLock;
    uint256 public claimAmount;
    uint256 public payAmount;
    uint256 public feeAmount;
    uint256 public epoch;
    uint256 public retentionMax;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public buried;
    mapping (address => uint256) public claimed;


    event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event Burn(address indexed _from, uint256 _value);
	event Bury(address indexed _target, uint256 _value);
	event Claim(address indexed _target, address indexed _payout, address indexed _fee);

     function EtherSpeed() public {
        director = msg.sender;
        name = "EtherSpeed";
        symbol = "ETS";
        decimals = 4;
        saleClosed = true;
        directorLock = false;
        funds = 0;
        totalSupply = 0;
        
        totalSupply += 5000000 * 10 ** uint256(decimals);
		balances[director] = totalSupply;
        claimAmount = 5 * 10 ** (uint256(decimals) - 1);
        payAmount = 4 * 10 ** (uint256(decimals) - 1);
        feeAmount = 1 * 10 ** (uint256(decimals) - 1);
        epoch = 31536000;
        retentionMax = 40 * 10 ** uint256(decimals);
    }
    
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
    modifier onlyDirector {
        require(!directorLock);
        
        require(msg.sender == director);
        _;
    }
    
    modifier onlyDirectorForce {
        require(msg.sender == director);
        _;
    }
    
    function transferDirector(address newDirector) public onlyDirectorForce {
        director = newDirector;
    }
    
    function withdrawFunds() public onlyDirectorForce {
        director.transfer(this.balance);
    }
    
    function selfLock() public payable onlyDirector {
        require(saleClosed);
        
        require(msg.value == 10 ether);
        
        directorLock = true;
    }
    
    function amendClaim(uint8 claimAmountSet, uint8 payAmountSet, uint8 feeAmountSet, uint8 accuracy) public onlyDirector returns (bool success) {
        require(claimAmountSet == (payAmountSet + feeAmountSet));
        
        claimAmount = claimAmountSet * 10 ** (uint256(decimals) - accuracy);
        payAmount = payAmountSet * 10 ** (uint256(decimals) - accuracy);
        feeAmount = feeAmountSet * 10 ** (uint256(decimals) - accuracy);
        return true;
    }
    
    function amendEpoch(uint256 epochSet) public onlyDirector returns (bool success) {
        epoch = epochSet;
        return true;
    }
    
    function amendRetention(uint8 retentionSet, uint8 accuracy) public onlyDirector returns (bool success) {
        retentionMax = retentionSet * 10 ** (uint256(decimals) - accuracy);
        return true;
    }
    
    function closeSale() public onlyDirector returns (bool success) {
        require(!saleClosed);
        
        saleClosed = true;
        return true;
    }

    function openSale() public onlyDirector returns (bool success) {
        require(saleClosed);
        
        saleClosed = false;
        return true;
    }
    
    function bury() public returns (bool success) {
        require(!buried[msg.sender]);
        require(balances[msg.sender] >= claimAmount);
        require(balances[msg.sender] <= retentionMax);
        buried[msg.sender] = true;
        claimed[msg.sender] = 1;
        Bury(msg.sender, balances[msg.sender]);
        return true;
    }
    
    function claim(address _payout, address _fee) public returns (bool success) {
        require(buried[msg.sender]);
        require(_payout != _fee);
        require(msg.sender != _payout);
        require(msg.sender != _fee);
        require(claimed[msg.sender] == 1 || (block.timestamp - claimed[msg.sender]) >= epoch);
        require(balances[msg.sender] >= claimAmount);
        claimed[msg.sender] = block.timestamp;
        uint256 previousBalances = balances[msg.sender] + balances[_payout] + balances[_fee];
        balances[msg.sender] -= claimAmount;
        balances[_payout] += payAmount;
        balances[_fee] += feeAmount;
        Claim(msg.sender, _payout, _fee);
        Transfer(msg.sender, _payout, payAmount);
        Transfer(msg.sender, _fee, feeAmount);
        assert(balances[msg.sender] + balances[_payout] + balances[_fee] == previousBalances);
        return true;
    }
    
    function () public payable {
        require(!saleClosed);
        require(msg.value >= 1 finney);
        uint256 amount = msg.value * 5000;
        require(totalSupply + amount <= (5000000 * 10 ** uint256(decimals)));
        totalSupply += amount;
        balances[msg.sender] += amount;
        funds += msg.value;
        Transfer(this, msg.sender, amount);
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(!buried[_from]);
        if (buried[_to]) {
            require(balances[_to] + _value <= retentionMax);
        }
        require(_to != 0x0);
        require(balances[_from] >= _value);
        require(balances[_to] + _value > balances[_to]);
        uint256 previousBalances = balances[_from] + balances[_to];
        balances[_from] -= _value;
        balances[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balances[_from] + balances[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(!buried[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(!buried[msg.sender]);
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(!buried[_from]);
        require(balances[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify token holder about burn operation before state changes
        // Manually simulating external unsafe callback by standard external call (no try/catch in 0.4.18)
        if (_from != address(0) && isContract(_from)) {
            // call returns (bool, bytes memory), but just ignore output for compatibility
            ITokenHolder(_from).onTokensBurned(_value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    // Helper to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}