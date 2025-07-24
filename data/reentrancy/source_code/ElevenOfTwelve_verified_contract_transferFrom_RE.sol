/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious contract with onTokenReceived callback
 * 2. **Transaction 2**: Attacker calls approve() to set allowance for the malicious contract
 * 3. **Transaction 3**: Attacker calls transferFrom() triggering the callback BEFORE state changes, allowing the malicious contract to call transferFrom() again recursively
 * 
 * The vulnerability is stateful because:
 * - It requires pre-existing allowances set in previous transactions
 * - The malicious contract's state persists between transactions
 * - The exploit relies on the accumulated allowance state from earlier approve() calls
 * - Multiple calls to transferFrom() can drain funds by exploiting the fact that state updates happen after the external call
 * 
 * This creates a classic reentrancy where the external call allows the attacker to re-enter the function before critical state variables (balances, allowed) are updated, enabling token draining across multiple recursive calls.
 */
pragma solidity ^0.4.12;

contract ElevenOfTwelve {
    
    // totalSupply = Maximum is 210000 Coins with 18 decimals;
    // Only 1/100 of the maximum bitcoin supply.
    // Nur 1/100 vom maximalen Bitcoin Supply.
    // ElevenOfTwelve IS A VERY SEXY COIN :-)
    // Buy and get rich!

    uint256 public totalSupply = 210000000000000000000000;
    uint256 public availableSupply= 210000000000000000000000;
    uint256 public circulatingSupply = 0;
    uint8   public decimals = 18;
  
    string  public standard = 'ERC20 Token';
    string  public name = 'ElevenOfTwelve';
    string  public symbol = '11of12';            
    uint256 public crowdsalePrice = 100;                          
    uint256 public crowdsaleClosed = 0;                 
    address public daoMultisig = msg.sender;
    address public owner = msg.sender;  

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Check if _to is a contract and has callback capability
            if (isContract(_to)) {
                // Call external contract before state changes - VULNERABILITY POINT
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
                // Continue regardless of callback success
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
    
    function () payable {
        require(crowdsaleClosed == 0);
        require(msg.value != 0);
        require(daoMultisig.send(msg.value));
        uint token = msg.value * crowdsalePrice;
        availableSupply = totalSupply - circulatingSupply;
        require(token <= availableSupply);
        circulatingSupply += token;
        balances[msg.sender] += token;
    }
    
    function setPrice(uint256 newSellPrice) onlyOwner {
        crowdsalePrice = newSellPrice;
    }
    
    function stoppCrowdsale(uint256 newStoppSign) onlyOwner {
        crowdsaleClosed = newStoppSign;
    }   

    function setMultisigAddress(address newMultisig) onlyOwner {
        daoMultisig = newMultisig;
    }

    // Helper to check if an address is a contract (works in 0.4.x)
    function isContract(address _addr) internal constant returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
