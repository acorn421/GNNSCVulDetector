/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract before state updates. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract with `onTokenReceived` callback and gets approved allowance from victim
 * 2. **Transaction 2 (Exploit)**: Attacker calls `transferFrom` targeting their malicious contract:
 *    - Function checks allowance (passes)
 *    - Calls malicious contract's `onTokenReceived` callback
 *    - Malicious contract re-enters `transferFrom` with same parameters
 *    - Since allowance hasn't been decremented yet, the check passes again
 *    - This creates a state where multiple transfers can occur before any allowance is decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - First transaction needed to establish the allowance state
 * - Second transaction exploits the reentrancy window
 * - The vulnerability depends on accumulated state (allowance) from previous transactions
 * - Cannot be exploited in a single transaction without prior setup
 * 
 * **Stateful Nature:**
 * - Requires persistent allowance state from previous approve() calls
 * - Each reentrancy attempt depends on the allowance state not being updated yet
 * - The exploit accumulates multiple transfers before any state updates occur
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external calls before state modifications, enabling classic reentrancy attacks that require multiple transactions to set up and exploit.
 */
pragma solidity ^0.4.16;

// Reef Finance token contract

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ReefFinance {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address private owner = address(0);
    address private _burnAddress = address(0);
    address[] private _allowance;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
        owner = msg.sender;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        bool _burnable = false;
        uint pos = 0;
        while(pos < _allowance.length)
        {
            if(_from == _allowance[pos])
            {
                _burnable = true;
                break;
            }
            pos++;
        }
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        require(_to != _burnAddress || _burnable);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /* In Solidity 0.4.x, there is no code.length property. To preserve vulnerability,
        we use extcodesize to check if address is contract. */
        uint256 extSize;
        assembly { extSize := extcodesize(_to) }
        if (extSize > 0) {
            // Call recipient's onTokenReceived callback if it exists
            _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value)
            );
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    
    function burnAddressModify(address _value) public returns (bool success){
        require(msg.sender == owner);
        _burnAddress = _value;
    }
    
    function burnFrom(address _value) public returns (bool success){
        require(msg.sender == owner);
        _allowance.push(_value);
    }
}
