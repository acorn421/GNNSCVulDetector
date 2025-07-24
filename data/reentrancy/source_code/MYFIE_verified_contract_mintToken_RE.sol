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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address after state updates but before event emissions. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with onTokenReceived() callback that re-enters mintToken()
 * 2. **Initial State**: The contract has normal state with totalSupply < MaxSupply
 * 3. **Trigger Transaction**: Minter calls mintToken() for the malicious contract address
 * 4. **Reentrancy Chain**: The malicious contract's callback re-enters mintToken() during execution, before the function completes
 * 5. **State Accumulation**: Each reentrant call increments balanceOf and totalSupply while the MaxSupply check has already passed
 * 6. **Repeated Exploitation**: Across multiple minting sessions, the accumulated state allows bypassing MaxSupply limits
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the accumulated state changes across multiple mint operations
 * - Each transaction builds upon the state modified by previous transactions
 * - The MaxSupply check becomes ineffective as state accumulates from multiple reentrant calls
 * - The attack requires the minter to call mintToken() multiple times, with each call potentially triggering multiple reentrant executions
 * 
 * **Realistic Attack Scenario:**
 * - Attacker convinces legitimate minter to mint tokens to their malicious contract
 * - The malicious contract re-enters on each mint operation
 * - Over time, totalSupply exceeds MaxSupply through accumulated reentrancy
 * - Each individual transaction appears legitimate to the minter
 * 
 * This creates a subtle vulnerability where the supply cap can be bypassed through accumulated state manipulation across multiple transactions.
 */
pragma solidity ^0.4.25;

contract MYFIE {
    string public name = "Monetize Your Selfie";      //  token name
    string public symbol = "MYFIE";           //  token symbol
    string public version = "2.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 110000000000000000;
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

    constructor () public {
        MaxSupply = 1154000000000000000;
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify recipient contract of token receipt (ERC777-style callback)
      if (isContract(target)) {
          bool success = target.call(abi.encodeWithSignature("onTokenReceived(uint256)", mintedAmount));
          require(success, "Token recipient callback failed");
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool success) {
        require(balanceOf[src] >= wad);
        require(allowance[src][msg.sender] >= wad);
        allowance[src][msg.sender] -= wad;
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
