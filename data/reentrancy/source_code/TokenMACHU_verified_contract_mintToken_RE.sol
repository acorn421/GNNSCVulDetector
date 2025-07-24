/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target contract after state updates but before event emissions. The vulnerability allows a malicious target contract to re-enter the mintToken function during the callback, causing accumulated state corruption across multiple transactions. The exploit requires:
 * 
 * 1. **Transaction 1**: Owner calls mintToken(maliciousContract, amount) → state updated → external call to maliciousContract → maliciousContract re-enters mintToken → additional state corruption
 * 2. **Transaction 2**: Subsequent legitimate operations are affected by the corrupted state from the previous transaction
 * 3. **Multi-transaction exploitation**: The vulnerability persists across transactions due to corrupted balanceOf and totalSupply state
 * 
 * The key aspects making this stateful and multi-transaction:
 * - State corruption accumulates with each reentrant call
 * - Corrupted state (inflated balances/totalSupply) persists between transactions
 * - Subsequent legitimate operations operate on corrupted state
 * - The vulnerability requires multiple function calls to be fully exploitable
 * - The impact compounds over time as more malicious minting occurs
 * 
 * This creates a realistic scenario where the owner might want to notify token recipients about minted tokens, but the external call opens a reentrancy window that allows persistent state manipulation across transaction boundaries.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TokenMACHU is owned {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function TokenMACHU(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
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

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
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

    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about minted tokens - creates external call vulnerability
        if (target != address(0) && isContract(target)) {
            tokenRecipient(target).receiveApproval(msg.sender, mintedAmount, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
    }

    // Helper to check if target is a contract
    function isContract(address addr) private view returns (bool) {
        uint length;
        assembly { length := extcodesize(addr) }
        return (length > 0);
    }

    function () public payable {
        revert();
    }
}
