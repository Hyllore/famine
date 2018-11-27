/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_read.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/14 15:55:31 by amaindro          #+#    #+#             */
/*   Updated: 2015/12/14 16:27:14 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <unistd.h>
#define BUF_SIZE 999999999

char	**ft_read(int fd, char c)
{
	int		ret;
	char	buf[BUF_SIZE + 1];
	char	**tab;

	ret = read(fd, buf, BUF_SIZE);
	buf[ret] = '\0';
	tab = ft_strsplit(buf, c);
	return (tab);
}
