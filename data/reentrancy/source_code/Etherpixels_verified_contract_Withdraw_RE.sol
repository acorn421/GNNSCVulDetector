/*
 * ===== SmartInject Injection Details =====
 * Function      : Withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase withdrawal system. The function now operates in two phases controlled by the `withdrawalPhase` boolean state variable:
 * 
 * **Phase 1 (withdrawalPhase = false):** 
 * - Initiates withdrawal by storing the requested amount in `pendingWithdrawals` mapping
 * - Updates `totalPendingWithdrawals` counter to track total pending amounts
 * - Sets `withdrawalPhase = true` to enable Phase 2
 * 
 * **Phase 2 (withdrawalPhase = true):**
 * - Executes the actual withdrawal of pending amounts
 * - Uses `call.value()` instead of `transfer()` to enable reentrancy
 * - Critically violates CEI pattern: external call happens BEFORE state cleanup
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1:** Call `Withdraw(100)` - enters Phase 1, sets pending withdrawal of 100, enables Phase 2
 * 2. **Transaction 2:** Call `Withdraw(0)` - enters Phase 2, makes external call to contract_owner
 * 3. **During external call:** If contract_owner is a malicious contract, it can reenter `Withdraw(200)` which goes to Phase 1 again (withdrawalPhase gets reset in the middle of Phase 2 execution)
 * 4. **Reentrancy effect:** Additional pending withdrawals can be accumulated before the original Phase 2 completes its state cleanup
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires building up pending withdrawal state across multiple transactions
 * - Each transaction can add to the accumulated pending amount before any cleanup occurs
 * - The reentrancy during Phase 2 allows returning to Phase 1 to manipulate state that persists between transactions
 * - Single transaction exploitation is impossible due to the phase-based state machine requiring separate calls
 * 
 * This creates a realistic vulnerability where accumulated state from previous transactions enables the exploit, making it a true stateful, multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.18;

contract usingOwnership {
  address public contract_owner;

  modifier onlyOwner() {
    require(msg.sender == contract_owner);
    _;
  }

  function usingOwnership() internal {
    contract_owner = msg.sender;
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
  uint public totalPendingWithdrawals;
  bool public withdrawalPhase = false;
  
  function Withdraw(uint _amount) onlyOwner public {
    if (!withdrawalPhase) {
      // Phase 1: Initiate withdrawal request
      if (_amount > this.balance - totalPendingWithdrawals)
        _amount = this.balance - totalPendingWithdrawals;
      
      pendingWithdrawals[contract_owner] += _amount;
      totalPendingWithdrawals += _amount;
      withdrawalPhase = true;
    } else {
      // Phase 2: Complete withdrawal
      uint amount = pendingWithdrawals[contract_owner];
      if (amount > 0) {
        // Vulnerable: external call before state update
        contract_owner.call.value(amount)("");
        // State updates happen after external call - too late!
        pendingWithdrawals[contract_owner] = 0;
        totalPendingWithdrawals -= amount;
        withdrawalPhase = false;
      }
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function TransferOwnership(address _new_owner) onlyOwner public {
    require(_new_owner != address(0));
    contract_owner = _new_owner;
  }
}

contract usingCanvasBoundaries {
  uint private g_block;
  uint private max_max_index;
  uint private max_block_number;
  uint[] private halving;
   
  function usingCanvasBoundaries() internal {
    g_block = block.number;
    max_max_index = 4198401;
    max_block_number = g_block + 3330049;
    halving = [g_block + 16384, g_block + 81920, g_block + 770048];
  }

  function max_index() internal view returns(uint m_index) {
    if (block.number > max_block_number)
      return max_max_index;
    uint delta = block.number - g_block;
    return delta +
    ((block.number <= halving[0]) ? delta : halving[0] - g_block) +
    ((block.number <= halving[1]) ? delta : halving[1] - g_block) +
    ((block.number <= halving[2]) ? delta : halving[2] - g_block);
  }

  function HalvingInfo() public view returns(uint genesis_block, uint[] halving_array) {
    return (g_block, halving);
  }
}

contract Etherpixels is usingOwnership, usingCanvasBoundaries {
  uint private starting_price = 5000000000000; /* 5000 gwei */

  /* packed to 32 bytes */
  struct Pixel {
    uint96 price;
    address owner;
  }
  
  mapping(uint => Pixel) private pixels;

  event PixelPainted(uint i, address new_owner, address old_owner, uint price, bytes3 new_color);
  event PixelUnavailable(uint i, address new_owner, uint price, bytes3 new_color);
  
  function Paint(uint _index, bytes3 _color) public payable {
    require(_index <= max_index());
    paint_pixel(_index, _color, msg.value);
  }

  function BatchPaint(uint8 _batch_size, uint[] _index, bytes3[] _color, uint[] _paid) public payable {
    uint remaining = msg.value;
    uint m_i = max_index();
    for(uint8 i = 0; i < _batch_size; i++) {
      require(remaining >= _paid[i] && _index[i] <= m_i);
      paint_pixel(_index[i], _color[i], _paid[i]);
      remaining -= _paid[i];
    }
  }

  function StartingPrice() public view returns(uint price) {
    return starting_price;
  }

  function LowerStartingPrice(uint _new_starting_price) onlyOwner public {
    require(_new_starting_price < starting_price);
    starting_price = _new_starting_price;
  }
  
  function paint_pixel(uint _index, bytes3 _color, uint _paid) private {
    Pixel storage p = pixels[_index];
    if (msg.sender == p.owner) {
      PixelPainted(_index, msg.sender, msg.sender, p.price, _color);
    }
    else {
      uint current_price = p.price == 0 ? starting_price : uint(p.price);
      if (_paid < current_price * 11 / 10)
        PixelUnavailable(_index, msg.sender, current_price, _color);
      else {
        if (_paid > current_price * 2)
          _paid = current_price * 2;
        p.price = uint96(_paid);
        require(p.price == _paid); /* casting guard */ 
        address old_owner = p.owner;
        p.owner = msg.sender;
        PixelPainted(_index, msg.sender, old_owner, p.price, _color);
        if (old_owner != address(0))
          old_owner.send(_paid * 98 / 100); /* not using transfer to avoid old_owner locking pixel by buying it from a contract that reverts when receiving funds */
      }
    }
  }
}