/* eslint-disable prettier/prettier */
import { User } from "src/auth/user.entity";
import { BaseEntity, Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { TaskStatus } from "./task-status.enum";

@Entity()
export class Task extends BaseEntity {
    @PrimaryGeneratedColumn()
    id: number;
  
    @Column()
    title: string;
  
    @Column()
    description: string;
  
    @Column()
    status: TaskStatus;
  
    @ManyToOne(()=> User, user => user.task, { eager: true })
    user: User;
  
    @Column()
    userId: number;
}