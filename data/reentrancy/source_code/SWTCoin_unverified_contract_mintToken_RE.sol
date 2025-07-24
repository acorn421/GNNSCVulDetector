/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address after state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional external call to the target address using `target.call(abi.encodeWithSignature("onTokenMinted(uint256)", mintedAmount))`
 * 2. The call is made AFTER state updates (balanceOf and totalSupply modifications)
 * 3. Added code.length check to only call contracts, making it more realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenMinted` function
 * 2. **Transaction 2**: Minter calls `mintToken` with malicious contract as target
 * 3. **During Transaction 2**: The malicious contract's `onTokenMinted` callback can:
 *    - Read the updated totalSupply value
 *    - Store state about previous minting operations
 *    - Prepare for future exploitation
 * 4. **Transaction 3+**: The malicious contract can use stored state from previous callbacks to:
 *    - Manipulate timing of subsequent mint operations
 *    - Coordinate with other contracts to bypass MaxSupply checks through race conditions
 *    - Accumulate information about minting patterns for targeted attacks
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - Each minting operation provides information that accumulates across transactions
 * - The callback mechanism allows the attacker to build state over multiple minting operations
 * - Race conditions between multiple minting transactions can be exploited by coordinating through the callback
 * - The MaxSupply check becomes vulnerable when multiple transactions are pending simultaneously
 * 
 * This creates a realistic stateful vulnerability where each transaction builds upon previous state, making single-transaction exploitation impossible while enabling sophisticated multi-transaction attacks.
 */
pragma solidity ^0.4.16;

contract SWTCoin {
    string public name = "SWTCoin";      //  token name
    string public symbol = "SWAT";           //  token symbol
    string public version = "1.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 29000000000000000;
    uint256 public MaxSupply = 0;
    bool public stopped = true;

    //000 000 000 000 000 000
    address owner = 0x48850F503412d8A6e3d63541F0e225f04b13a544;
    address minter = 0x47c803871c99EC7180E50dcDA989320871FcBfEE;
    
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isMinter {
        assert(minter == msg.sender);
        _;
    }
    
    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function SWTCoin() public {
        MaxSupply = 154000000000000000;
        balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function changeOwner(address _newaddress) isOwner public {
        owner = _newaddress;
    }

    function changeMinter(address _new_mint_address) isOwner public {
        minter = _new_mint_address;
    }
    
    function airdropMinting(address[] _to_list, uint[] _values) isMinter public {
        require(_to_list.length == _values.length);
        for (uint i = 0; i < _to_list.length; i++) {
            mintToken(_to_list[i], _values[i]);
        }
    }

    function setMaxSupply(uint256 maxsupply_amount) isOwner public {
      MaxSupply = maxsupply_amount;
    }

    function mintToken(address target, uint256 mintedAmount) isMinter public {
      require(MaxSupply > totalSupply);
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify target of minting - potential reentrancy point
      // (In Solidity 0.4.16, use extcodesize for contract check instead of code property)
      uint256 size;
      assembly { size := extcodesize(target) }
      if (size > 0) {
          target.call(bytes4(keccak256("onTokenMinted(uint256)")), mintedAmount);
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
