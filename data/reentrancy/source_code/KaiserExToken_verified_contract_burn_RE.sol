/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending burns system with external callbacks. The vulnerability requires multiple transactions to exploit: (1) First transaction registers a malicious callback contract, (2) Second transaction calls burn() which triggers the callback before finalizing state updates, (3) The callback can re-enter burn() to accumulate more pending burns, (4) When the original burn() resumes, it processes all accumulated pending burns at once, potentially burning more tokens than the attacker actually owns. The vulnerability depends on the pendingBurns state persisting between transactions and the callback being executed before proper state cleanup.
 */
pragma solidity ^0.4.16;

interface IBurnCallback {
    function onBurnNotification(address user, uint256 value) external;
}

contract KaiserExToken {

    string public name;
    string public symbol;
    uint8 public decimals = 18;

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 60000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "KaiserEx Token";
        symbol = "KET";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
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
        allowance[msg.sender][_spender] = _value;
        return true;
    }
     
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => uint256) public pendingBurns;
    mapping (address => address) public burnCallbacks;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        
        // Add to pending burns for multi-transaction processing
        pendingBurns[msg.sender] += _value;
        
        // If callback is registered, notify before finalizing burn
        if (burnCallbacks[msg.sender] != address(0)) {
            // External call before state finalization - vulnerable to reentrancy
            IBurnCallback(burnCallbacks[msg.sender]).onBurnNotification(msg.sender, _value);
        }
        
        // Process all pending burns for this user
        uint256 totalPendingBurn = pendingBurns[msg.sender];
        if (balanceOf[msg.sender] >= totalPendingBurn) {
            balanceOf[msg.sender] -= totalPendingBurn;
            totalSupply -= totalPendingBurn;
            pendingBurns[msg.sender] = 0;
            Burn(msg.sender, totalPendingBurn);
        }
        
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function registerBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
     
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
